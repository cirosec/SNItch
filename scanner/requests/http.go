package requests

import (
	"context"
	"crypto/tls"
	"github.com/cirosec/snitch/dns"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"
)

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func ExtractHTMLTitle(r *http.Response) string {
	// Yes I am aware of it: https://stackoverflow.com/questions/1732348/regex-match-open-tags-except-xhtml-self-contained-tags/1732454#1732454
	// This is intended as a simple way to get the document title in most cases. Hence a regex is fine from my perspective
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	matches := titleRegex.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func MakeHTTPRequest(resolver dns.DNSResolver, target, SNI string, timeout time.Duration, userAgent string) (int, *http.Response, error) {
	sniToSet := "127.0.0.1" // see https://gist.github.com/delthas/6447f11a0f796b79e0f5f74dc6d6ef2a#file-sni-go-L10-L12
	if SNI != "" {
		sniToSet = SNI
	}
	req, _ := http.NewRequest("GET", "https://"+target, nil)

	req.Host = sniToSet
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	dialer := &net.Dialer{Timeout: timeout}
	client := http.Client{
		Timeout: timeout,
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, resolveTarget(resolver, addr))
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
