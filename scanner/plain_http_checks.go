package scanner

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/scanner/requests"
)

// plainHTTPVariant is one plaintext HTTP probe. Hosted variants carry a
// specific Host header; the NoHost variant sends an RFC 1945-era HTTP/1.0
// request without any Host header at all.
type plainHTTPVariant struct {
	Host     string
	Random   bool // Whether Host is the generated random-hostname probe
	NoHost   bool // Whether this is the Host-less HTTP/1.0 probe
	Status   int
	Title    string
	Redirect string
}

// probePlainHTTPPort sends plaintext HTTP requests to the given port of the
// target IP using four variants: three Host header variants (the IP itself, a
// random hostname and an invalid hostname) plus a Host-less HTTP/1.0 request.
// Any hostname revealed via the Location header (and, when --search-headers is
// set, the body or other headers) is fed back into the recon queue. It returns
// the most informative revealed variant. cancelled reports that the scan was
// aborted mid-probe; callers must then discard the result.
func (sTC *ScannerRootResult) probePlainHTTPPort(ctx context.Context, port string) (chosen plainHTTPVariant, revealed bool, cancelled bool) {
	ip, _, err := net.SplitHostPort(sTC.Target)
	if err != nil {
		ip = sTC.Target
	}

	variants := []plainHTTPVariant{
		{Host: ip},
		{Host: helpers.RandStringBytes(10) + ".com", Random: true},
		{Host: "$"},
		{NoHost: true},
	}

	chosenSet := false
	for _, variant := range variants {
		if ctx.Err() != nil {
			return chosen, revealed, true
		}
		variantHost := variant.Host
		var status int
		var resp *http.Response
		var reqErr error
		if variant.NoHost {
			status, resp, reqErr = requests.MakeNoHostHTTPRequest(
				ctx,
				sTC.gctx.DNSresolver,
				sTC.Target,
				port,
				sTC.gctx.Timeout,
				sTC.gctx.UserAgent,
			)
		} else {
			status, resp, reqErr = requests.MakePlainHTTPRequest(
				ctx,
				sTC.gctx.DNSresolver,
				sTC.Target,
				variantHost,
				port,
				sTC.gctx.Timeout,
				sTC.gctx.UserAgent,
			)
		}
		if reqErr != nil || resp == nil {
			sTC.gctx.DebugLog.PlainHTTPRequest(sTC.Target, variantHost, port, -1, "", "", reqErr)
			continue
		}

		redirect := resp.Header.Get("Location")
		body := requests.ReadBody(resp)
		title := requests.TitleFromBody(body)
		sTC.gctx.DebugLog.PlainHTTPRequest(sTC.Target, variantHost, port, status, title, redirect, nil)

		// Feed any revealed hostname back into the recon queue. The requested
		// host itself is disallowed, so a server that merely reflects it back
		// does not create a phantom finding.
		variantRevealed := false
		if redirectHost, err := redirectValidate(redirect, variantHost); err == nil && redirectHost != "" && net.ParseIP(redirectHost) == nil {
			// A redirect to https://<ip>/ reveals no domain; only feed
			// hostnames back into the recon queue.
			sTC.gctx.AddRedirect(redirectHost)
			variantRevealed = true
		}
		if len(extractHeaderHosts(resp, sTC.gctx, variantHost)) > 0 {
			variantRevealed = true
		}
		if sTC.gctx.SearchHeaders {
			for _, host := range requests.ExtractBodyHosts(body) {
				// The reflection filter needs a requested host to compare
				// against; the Host-less variant has none, so every domain
				// in the body is a genuine reveal.
				if variantHost != "" && strings.Contains(host, strings.ToLower(variantHost)) {
					continue
				}
				sTC.gctx.AddHeaderHost(host)
				variantRevealed = true
			}
		}

		if !variantRevealed {
			continue
		}
		revealed = true

		current := plainHTTPVariant{Host: variantHost, Random: variant.Random, NoHost: variant.NoHost, Status: status, Title: title, Redirect: redirect}
		// Prefer a variant that shows a redirect, otherwise keep the first
		// variant that revealed something.
		if !chosenSet || (chosen.Redirect == "" && current.Redirect != "") {
			chosen = current
			chosenSet = true
		}
	}

	return chosen, revealed, false
}

// checkPlainHTTP sends plaintext HTTP requests to the target IP (on the
// configured HTTP port) using three Host header variants: the IP itself, a
// random hostname and an invalid hostname. The most informative variant is
// stored for the (HTTP) result row.
//
// A result is only worth reporting when it reveals a domain that was not
// already known from the request itself. An https://<ip>/ upgrade or a bare
// 404 carries no new information and must not create a row.
func (sTC *ScannerRootResult) checkPlainHTTP(ctx context.Context) {
	chosen, revealed, cancelled := sTC.probePlainHTTPPort(ctx, sTC.httpPort)
	if cancelled || !revealed {
		return
	}
	sTC.PlainHTTPHost = chosen.Host
	sTC.PlainHTTPHostRandom = chosen.Random
	sTC.PlainHTTPHostNoHost = chosen.NoHost
	sTC.PlainHTTPStatus = chosen.Status
	sTC.PlainHTTPTitle = chosen.Title
	sTC.PlainHTTPRedirect = chosen.Redirect
}

// checkPlainHTTPTLS sends the same plaintext HTTP probes to the target's own
// (TLS) port. A server that answers plaintext HTTP on its TLS port and leaks a
// hostname there is a distinct misconfiguration from the plain-HTTP port, so
// any revealed hostname is fed back into recon as an additional leak source.
//
// Nothing is reported when the probe reveals no hostname - notably the standard
// "400 The plain HTTP request was sent to HTTPS port" rejection emitted by
// nginx/Caddy.
func (sTC *ScannerRootResult) checkPlainHTTPTLS(ctx context.Context) {
	port := targetPort(sTC.Target)
	if port == "" || port == sTC.httpPort {
		// Without a distinct target port the probe would only repeat the
		// configured HTTP-port probe.
		return
	}
	chosen, revealed, cancelled := sTC.probePlainHTTPPort(ctx, port)
	if cancelled || !revealed {
		return
	}
	sTC.PlainHTTPTLSHost = chosen.Host
	sTC.PlainHTTPTLSHostRandom = chosen.Random
	sTC.PlainHTTPTLSHostNoHost = chosen.NoHost
	sTC.PlainHTTPTLSStatus = chosen.Status
	sTC.PlainHTTPTLSTitle = chosen.Title
	sTC.PlainHTTPTLSRedirect = chosen.Redirect
}

// targetPort returns the port portion of an ip:port target, or "" when the
// target carries no parseable port.
func targetPort(target string) string {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	return port
}
