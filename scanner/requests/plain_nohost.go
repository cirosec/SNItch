package requests

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/helpers"
)

// MakeNoHostHTTPRequest performs a plaintext HTTP/1.0 request with no Host
// header — the RFC 1945-era form "GET / HTTP/1.0". Go's net/http client cannot
// omit the Host header (it always fills one in), so the request is written to
// a raw connection and the response parsed with http.ReadResponse. Sending it
// as HTTP/1.0 matters: the RFC 9112 Section 3.2 requirement to reject
// Host-less requests with 400 is scoped to HTTP/1.1, and nginx, lighttpd and
// Go-based front ends enforce exactly that split.
//
// The probe targets servers that construct self-referential redirects from the
// request host (nginx absolute_redirect, Apache UseCanonicalName, lighttpd
// server.name): with no host information in the request at all, they fall back
// to their own configured server name and leak it in the Location header.
//
// The response body is fully consumed here (bounded by maxBodySize) and the
// underlying connection closed before returning; resp.Body is replaced with a
// buffer so callers can still read it after the raw connection is gone.
func MakeNoHostHTTPRequest(ctx context.Context, resolver dns.DNSResolver, target, httpPort string, timeout time.Duration, userAgent string) (int, *http.Response, error) {
	ip, _, err := net.SplitHostPort(target)
	if err != nil {
		ip = target
	}
	addr := net.JoinHostPort(ip, httpPort)

	dialer := &net.Dialer{Timeout: timeout}
	resolved, resolveErr := resolveTarget(resolver, addr)
	if resolveErr != nil {
		return -1, nil, resolveErr
	}
	conn, err := dialer.DialContext(ctx, "tcp", resolved)
	if err != nil {
		return -1, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Cancelled contexts abort the connection so response reads cannot
	// outlive the scan; the deadline above bounds the non-cancelled case.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stopWatch:
		}
	}()

	// A raw write bypasses net/http's header sanitization, so any CR/LF in a
	// user-supplied agent string must be stripped to prevent request smuggling
	// via the User-Agent header.
	ua := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, helpers.ResolveUserAgent(userAgent))

	request := "GET / HTTP/1.0\r\nUser-Agent: " + ua + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return -1, nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return -1, nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()
	if err != nil {
		return -1, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp.StatusCode, resp, nil
}