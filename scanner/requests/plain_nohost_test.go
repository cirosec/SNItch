package requests

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Host-less probe must arrive as a genuine RFC 1945-era request: HTTP/1.0
// request line, no Host header at all, so that servers fall back to their
// configured server name when constructing responses.
func TestMakeNoHostHTTPRequest_SendsNoHostOverHTTP10(t *testing.T) {
	type record struct {
		proto  string
		host   string
		method string
	}
	var got record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = record{proto: r.Proto, host: r.Host, method: r.Method}
		w.Header().Set("Location", "https://configured-name.example/")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	status, resp, err := MakeNoHostHTTPRequest(
		context.Background(),
		testResolver(),
		"127.0.0.1:443", // scanned TLS target; only the IP is reused
		port,
		5*time.Second,
		"",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusMovedPermanently {
		t.Fatalf("expected 301, got %d", status)
	}
	if loc := resp.Header.Get("Location"); loc != "https://configured-name.example/" {
		t.Fatalf("unexpected Location %q", loc)
	}
	ReadBody(resp)

	if got.method != "GET" {
		t.Fatalf("expected GET, got %q", got.method)
	}
	if got.proto != "HTTP/1.0" {
		t.Fatalf("expected request over HTTP/1.0, got %q", got.proto)
	}
	if got.host != "" {
		t.Fatalf("expected no Host header, got %q", got.host)
	}
}

// The raw connection must outlive body consumption: a body larger than the
// bufio read-ahead must be fully readable by the caller after the function
// returned (the body is buffered inside and the connection closed there).
func TestMakeNoHostHTTPRequest_LargeBodyReadable(t *testing.T) {
	const bodySize = 64 * 1024
	payload := strings.Repeat("A", bodySize)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	_, resp, err := MakeNoHostHTTPRequest(
		context.Background(),
		testResolver(),
		"127.0.0.1:443",
		port,
		5*time.Second,
		"",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := ReadBody(resp)
	if len(body) != bodySize {
		t.Fatalf("expected full %d-byte body, got %d bytes", bodySize, len(body))
	}
	if strings.Trim(body, "A") != "" {
		t.Fatalf("unexpected body content")
	}
}
