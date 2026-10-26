package scanner

import (
	"context"
	"errors"
	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/scanner/requests"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func (r *ScannerRootResult) checkHTTP(ctx context.Context) {
	random1 := helpers.RandStringBytes(10) + ".com"
	statusCode, resp, err := requests.MakeHTTPRequest(
		ctx,
		r.gctx.DNSresolver,
		r.Target,
		random1,
		r.gctx.Timeout,
		r.gctx.UserAgent,
	)
	if err == nil && resp != nil {
		title := requests.ExtractHTMLTitle(resp)
		location := resp.Header.Get("Location")
		r.HttpStatus = statusCode
		r.HttpTitle = title
		r.HttpRedirect = strings.ReplaceAll(strings.ToLower(location), strings.ToLower(random1), "*")
		// A redirect that echoes the random Host back is a reflection, not a
		// real hostname; flag the target so redirect-based rows are suppressed.
		if reflectsHost(location, random1) {
			r.HTTPReflectsHost = true
			r.gctx.MarkHTTPReflectingTarget(r.Target)
		}
		r.gctx.DebugLog.HTTPRequest(r.Target, random1, statusCode, title, r.HttpRedirect, nil)
		if h, err := redirectValidate(location, random1); err == nil && h != "" {
			r.gctx.AddRedirect(h)
		}
		extractHeaderHosts(resp, r.gctx, random1)
	} else {
		r.gctx.DebugLog.HTTPRequest(r.Target, random1, -1, "", "", err)
	}
}

func (sHC *ScannerHostnameResult) checkHTTP(ctx context.Context, target string) {
	statusCode, resp, err := requests.MakeHTTPRequest(
		ctx,
		sHC.gctx.DNSresolver,
		target,
		sHC.hostname,
		sHC.gctx.Timeout,
		sHC.gctx.UserAgent,
	)
	if err == nil && resp != nil {
		title := requests.ExtractHTMLTitle(resp)
		sHC.HttpStatus = statusCode
		sHC.HttpTitle = title
		sHC.HttpRedirect = resp.Header.Get("Location")
		sHC.gctx.DebugLog.HTTPRequest(target, sHC.hostname, statusCode, title, sHC.HttpRedirect, nil)
		if redirectHostname, err := redirectValidate(resp.Header.Get("Location"), ""); err == nil && redirectHostname != "" {
			sHC.gctx.AddRedirect(redirectHostname)
		}
		extractHeaderHosts(resp, sHC.gctx, "")
	} else {
		sHC.gctx.DebugLog.HTTPRequest(target, sHC.hostname, -1, "", "", err)
	}
}

func (sWC *ScannerSubdomainResult) checkHTTP(ctx context.Context, target string) {
	domain := strings.TrimPrefix(sWC.wildcardDomain, "*.")
	random1 := helpers.RandStringBytes(4)
	randDomain := random1 + "." + domain
	statusCode, resp, err := requests.MakeHTTPRequest(ctx, sWC.gctx.DNSresolver, target,
		randDomain,
		sWC.gctx.Timeout,
		sWC.gctx.UserAgent,
	)
	if err == nil && resp != nil {
		title := requests.ExtractHTMLTitle(resp)
		location := resp.Header.Get("Location")
		sWC.HttpStatus = statusCode
		sWC.HttpTitle = title
		sWC.HttpRedirect = strings.ReplaceAll(strings.ToLower(location), strings.ToLower(randDomain), sWC.wildcardDomain)
		// The server reflects the requested Host into its redirect: the
		// "wildcard" is not real, so it must not produce a row.
		if reflectsHost(location, randDomain) {
			sWC.HTTPReflectsHost = true
			sWC.gctx.MarkHTTPReflectingTarget(target)
		}
		sWC.gctx.DebugLog.HTTPRequest(target, randDomain, statusCode, title, sWC.HttpRedirect, nil)

		// Checks if the redirect host is just the random host. If so ignore it because then the server just reflects the hostname as redirect
		if redirectHostname, err := redirectValidate(location, random1); err == nil && redirectHostname != "" {
			sWC.gctx.AddRedirect(redirectHostname)
		}
		extractHeaderHosts(resp, sWC.gctx, random1)
	} else {
		sWC.gctx.DebugLog.HTTPRequest(target, randDomain, -1, "", "", err)
	}
}

// reflectsHost reports whether an HTTP redirect targets the exact host that was
// requested — i.e. the server echoed the Host header back (a reflecting
// catch-all) rather than redirecting to a real, distinct hostname.
func reflectsHost(location, requested string) bool {
	if location == "" || requested == "" {
		return false
	}
	return strings.Contains(strings.ToLower(location), strings.ToLower(requested))
}

// redirectValidate returns the hostname of the redirect URL if the redirect is not to the host specified as disallowedHostSubstring. Otherwise it returns an empty string
func redirectValidate(redirectURL string, disallowedHostSubstring string) (string, error) {
	if len(redirectURL) == 0 {
		return "", errors.New("empty redirect")
	}
	parsedRedirectURL, err := url.Parse(redirectURL)
	if err != nil {
		return "", err
	}
	redirectHostname := parsedRedirectURL.Hostname()
	redirectHostname = strings.ToLower(redirectHostname)
	disallowedHostSubstring = strings.ToLower(disallowedHostSubstring)
	if len(disallowedHostSubstring) == 0 || !strings.Contains(redirectHostname, disallowedHostSubstring) {
		return redirectHostname, nil
	}
	return "", errors.New("host not reasonable")
}

var urlInHeaderRegex = regexp.MustCompile(`https?://[^\s;,>"'` + "`" + `]+`)

// extractHeaderHosts searches all HTTP response headers for URLs, adds any
// discovered hostnames to the global context and returns them. Headers like
// Location are already handled separately; this provides broader coverage when
// enabled. The returned hostnames are always non-empty and never IP literals.
func extractHeaderHosts(resp *http.Response, gctx *globalcontext.GlobalContext, disallowedSubstring string) []string {
	found := []string{}
	if resp == nil || !gctx.SearchHeaders {
		return found
	}
	for name, values := range resp.Header {
		// Skip Location — already handled by redirect logic
		if strings.EqualFold(name, "Location") {
			continue
		}
		if strings.EqualFold(name, "Set-Cookie") {
			for _, val := range values {
				found = append(found, extractCookieDomains(val, gctx, disallowedSubstring)...)
			}
		}
		for _, val := range values {
			for _, rawURL := range urlInHeaderRegex.FindAllString(val, -1) {
				parsed, err := url.Parse(rawURL)
				if err != nil {
					continue
				}
				host := strings.ToLower(parsed.Hostname())
				if host == "" || net.ParseIP(host) != nil {
					continue
				}
				if len(disallowedSubstring) > 0 && strings.Contains(host, strings.ToLower(disallowedSubstring)) {
					continue
				}
				gctx.AddHeaderHost(host)
				found = append(found, host)
			}
		}
	}
	return found
}

// extractCookieDomains parses a Set-Cookie header value for Domain attributes
// and registers the named domain as a discovered hostname. The Domain
// attribute pins the cookie to the operator's registrable domain — e.g.
// "Set-Cookie: sess=x; Domain=.example.com" reveals example.com even when the
// response was elicited under an attacker-chosen Host. The attribute is not a
// URL, so the generic http(s):// header regex never sees it. Per RFC 6265
// Section 5.2, if a value carries more than one Domain attribute, the last one
// wins.
func extractCookieDomains(setCookieValue string, gctx *globalcontext.GlobalContext, disallowedSubstring string) []string {
	host := ""
	for _, attr := range strings.Split(setCookieValue, ";") {
		key, val, ok := strings.Cut(attr, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Domain") {
			continue
		}
		// RFC 6265 allows a leading dot ("Domain=.example.com"); SNItch wants the bare name.
		host = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(val)), ".")
	}
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	if len(disallowedSubstring) > 0 && strings.Contains(host, strings.ToLower(disallowedSubstring)) {
		return nil
	}
	gctx.AddHeaderHost(host)
	return []string{host}
}
