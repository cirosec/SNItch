package requests

import (
	"context"
	"crypto/tls"
	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/helpers"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
var urlRegex = regexp.MustCompile(`https?://[^\s;,>"'` + "`" + `)]+`)

// maxBodySize caps response bodies read into memory so hostile or misbehaving
// servers cannot exhaust the tool's memory.
const maxBodySize = 1 << 20

// ReadBody reads and closes the response body once. Callers that need both the
// title and the body contents (e.g. to scrape hostnames) should read it here
// instead of calling ExtractHTMLTitle, which would consume the body.
func ReadBody(r *http.Response) string {
	if r == nil || r.Body == nil {
		return ""
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		return ""
	}
	return string(body)
}

// ExtractHTMLTitle returns the document title. It consumes the response body;
// use ReadBody when the body is needed for more than the title.
func ExtractHTMLTitle(r *http.Response) string {
	// Yes I am aware of it: https://stackoverflow.com/questions/1732348/regex-match-open-tags-except-xhtml-self-contained-tags/1732454#1732454
	// This is intended as a simple way to get the document title in most cases. Hence a regex is fine from my perspective
	body := ReadBody(r)
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// TitleFromBody extracts the HTML title from an already-read body string.
func TitleFromBody(body string) string {
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractBodyHosts returns the hostnames of every http(s) URL found in the
// given body. IP literals and empty hosts are skipped. This covers redirects
// expressed in the page content (meta refresh, canonical/og:url, absolute
// links) which are invisible in the Location header.
func ExtractBodyHosts(body string) []string {
	hosts := []string{}
	for _, rawURL := range urlRegex.FindAllString(body, -1) {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

// MakeNoSNIHTTPRequest performs an HTTPS request without sending the SNI
// extension and uses the target's IP as the Host header, mirroring a plain
// `curl https://<ip>`. An IP literal in ServerName makes Go omit SNI.
func MakeNoSNIHTTPRequest(ctx context.Context, resolver dns.DNSResolver, target string, timeout time.Duration, userAgent string) (int, *http.Response, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	// An IPv6 literal in ServerName makes Go omit SNI. The HTTP Host header
	// must bracket IPv6 literals, otherwise the server rejects the request
	// with 400 Bad Request.
	hostHeader := host
	if strings.Contains(host, ":") {
		hostHeader = "[" + strings.Trim(host, "[]") + "]"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+target, nil)
	if err != nil {
		return -1, nil, err
	}

	req.Host = hostHeader
	helpers.SetUserAgent(req, userAgent)

	dialer := &net.Dialer{Timeout: timeout}
	client := http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				resolved, rerr := resolveTarget(resolver, addr)
				if rerr != nil {
					return nil, rerr
				}
				return dialer.DialContext(ctx, network, resolved)
			},
			TLSHandshakeTimeout: timeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host, // IP => no SNI extension is sent
				MinVersion:         tls.VersionTLS10,
			},
		},
	}

	r, err := client.Do(req)
	if err != nil {
		_, err = ErrorHandlerConn(err)
		return -1, nil, err
	}
	return r.StatusCode, r, nil
}

// MakePlainHTTPRequest performs a plaintext HTTP request to the target IP,
// replacing the scanned port with httpPort (typically 80). The Host header is
// sent verbatim — including non-RFC values such as "$" — so a server's reaction
// to an unknown or invalid Host can be observed. No TLS is involved.
func MakePlainHTTPRequest(ctx context.Context, resolver dns.DNSResolver, target, hostHeader, httpPort string, timeout time.Duration, userAgent string) (int, *http.Response, error) {
	ip, _, err := net.SplitHostPort(target)
	if err != nil {
		ip = target
	}
	addr := net.JoinHostPort(ip, httpPort)

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr, nil)
	if err != nil {
		return -1, nil, err
	}
	req.Host = bracketHostHeader(hostHeader)
	helpers.SetUserAgent(req, userAgent)

	dialer := &net.Dialer{Timeout: timeout}
	client := http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				resolved, rerr := resolveTarget(resolver, addr)
				if rerr != nil {
					return nil, rerr
				}
				return dialer.DialContext(ctx, network, resolved)
			},
			TLSHandshakeTimeout: timeout,
		},
	}

	r, err := client.Do(req)
	if err != nil {
		_, err = ErrorHandlerConn(err)
		return -1, nil, err
	}
	return r.StatusCode, r, nil
}

// bracketHostHeader wraps bare IPv6 literals in brackets so they are valid as
// an HTTP Host header value. Hostnames and IPv4 values are returned unchanged.
func bracketHostHeader(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func MakeHTTPRequest(ctx context.Context, resolver dns.DNSResolver, target, SNI string, timeout time.Duration, userAgent string) (int, *http.Response, error) {
	sniToSet := "127.0.0.1" // see https://gist.github.com/delthas/6447f11a0f796b79e0f5f74dc6d6ef2a#file-sni-go-L10-L12
	if SNI != "" {
		sniToSet = SNI
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+target, nil)
	if err != nil {
		return -1, nil, err
	}

	req.Host = sniToSet
	helpers.SetUserAgent(req, userAgent)

	dialer := &net.Dialer{Timeout: timeout}
	client := http.Client{
		Timeout: timeout,
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				resolved, rerr := resolveTarget(resolver, addr)
				if rerr != nil {
					return nil, rerr
				}
				return dialer.DialContext(ctx, network, resolved)
			},
			TLSHandshakeTimeout: timeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         sniToSet,
				MinVersion:         tls.VersionTLS10,
			},
		},
	}

	r, err := client.Do(req)

	if err != nil {
		_, err = ErrorHandlerConn(err)
		//fmt.Printf("\n%+v\n", err)
		return -1, nil, err
	}
	return r.StatusCode, r, err
}
