package scanner

import (
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

func (r *ScannerRootResult) checkHTTP() {
	random1 := helpers.RandStringBytes(10) + ".com"
	statusCode, resp, err := requests.MakeHTTPRequest(
		r.gctx.DNSresolver,
		r.Target,
		random1,
		r.gctx.Timeout,
		r.gctx.UserAgent,
	)
	if err == nil && resp != nil {
		title := requests.ExtractHTMLTitle(resp)
		r.HttpStatus = statusCode
		r.HttpTitle = title
		r.HttpRedirect = strings.ReplaceAll(strings.ToLower(resp.Header.Get("Location")), strings.ToLower(random1), "*")
		r.gctx.DebugLog.HTTPRequest(r.Target, random1, statusCode, title, r.HttpRedirect, nil)
		if h, err := redirectValidate(resp.Header.Get("Location"), random1); err == nil && h != "" {
			r.gctx.AddRedirect(h)
		}
		extractHeaderHosts(resp, r.gctx, random1)
	} else {
		r.gctx.DebugLog.HTTPRequest(r.Target, random1, -1, "", "", err)
	}
}

func (sHC *ScannerHostnameResult) checkHTTP(target string) {
	statusCode, resp, err := requests.MakeHTTPRequest(
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

func (sWC *ScannerSubdomainResult) checkHTTP(target string) {
	domain := strings.TrimPrefix(sWC.wildcardDomain, "*.")
	random1 := helpers.RandStringBytes(4)
	randDomain := random1 + "." + domain
	statusCode, resp, err := requests.MakeHTTPRequest(sWC.gctx.DNSresolver, target,
		randDomain,
		sWC.gctx.Timeout,
		sWC.gctx.UserAgent,
	)
	if err == nil && resp != nil {
		title := requests.ExtractHTMLTitle(resp)
		sWC.HttpStatus = statusCode
		sWC.HttpTitle = title
		sWC.HttpRedirect = strings.ReplaceAll(strings.ToLower(resp.Header.Get("Location")), strings.ToLower(randDomain), sWC.wildcardDomain)
		sWC.gctx.DebugLog.HTTPRequest(target, randDomain, statusCode, title, sWC.HttpRedirect, nil)

		// Checks if the redirect host is just the random host. If so ignore it because then the server just reflects the hostname as redirect
		if redirectHostname, err := redirectValidate(resp.Header.Get("Location"), random1); err == nil && redirectHostname != "" {
			sWC.gctx.AddRedirect(redirectHostname)
		}
		extractHeaderHosts(resp, sWC.gctx, random1)
	} else {
		sWC.gctx.DebugLog.HTTPRequest(target, randDomain, -1, "", "", err)
	}
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

// extractHeaderHosts searches all HTTP response headers for URLs and adds
// any discovered hostnames to the global context. Headers like Location are
// already handled separately; this provides broader coverage when enabled.
func extractHeaderHosts(resp *http.Response, gctx *globalcontext.GlobalContext, disallowedSubstring string) {
	if resp == nil || !gctx.SearchHeaders {
		return
	}
	for name, values := range resp.Header {
		// Skip Location — already handled by redirect logic
		if strings.EqualFold(name, "Location") {
			continue
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
			}
		}
	}
}
