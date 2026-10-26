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

// TestMakePlainHTTPRequest_HostVariants verifies the three probe variants are
// sent as the Host header verbatim, including the non-RFC value "$", and that
// the request really is plaintext HTTP (no TLS).
func TestMakePlainHTTPRequest_HostVariants(t *testing.T) {
	var gotHosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHosts = append(gotHosts, r.Host)
		w.Header().Set("Location", "https://real.internal.example/login")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	variants := []string{"127.0.0.1", "randomhost.com", "$"}
	for _, variant := range variants {
		status, resp, err := MakePlainHTTPRequest(
			context.Background(),
			testResolver(),
			"127.0.0.1:443", // scanned TLS target; only the IP is reused
			variant,
			port,
			5*time.Second,
			"",
		)
		if err != nil {
			t.Fatalf("variant %q: unexpected error: %v", variant, err)
		}
		if status != http.StatusMovedPermanently {
			t.Fatalf("variant %q: expected 301, got %d", variant, status)
		}
		if loc := resp.Header.Get("Location"); loc != "https://real.internal.example/login" {
			t.Fatalf("variant %q: unexpected Location %q", variant, loc)
		}
		ReadBody(resp)
	}

	if len(gotHosts) != len(variants) {
		t.Fatalf("expected %d requests, got %d (%v)", len(variants), len(gotHosts), gotHosts)
	}
	for i, variant := range variants {
		if gotHosts[i] != variant {
			t.Fatalf("request %d: expected Host %q, got %q", i, variant, gotHosts[i])
		}
	}
}

// TestExtractBodyHosts verifies hostnames hidden in page content are found
// while IP literals and relative references are ignored.
func TestExtractBodyHosts(t *testing.T) {
	body := `<html><head><title>t</title>` +
		`<meta http-equiv="refresh" content="0;url=https://meta.example.com/x">` +
		`<link rel="canonical" href="https://canon.example.com/page">` +
		`</head><body><a href="http://link.example.com">l</a>` +
		`<a href="/relative">r</a><a href="https://10.0.0.1/admin">ip</a></body></html>`

	hosts := ExtractBodyHosts(body)
	want := map[string]bool{"meta.example.com": true, "canon.example.com": true, "link.example.com": true}
	for _, h := range hosts {
		delete(want, h)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected hosts: %v (got %v)", want, hosts)
	}
	for _, h := range hosts {
		if h == "10.0.0.1" {
			t.Fatalf("IP literal should be skipped, got %v", hosts)
		}
	}
}

// TestTitleFromBody ensures reading the body once still yields the title.
func TestTitleFromBody(t *testing.T) {
	if got := TitleFromBody("<html><title>Hello World</title></html>"); got != "Hello World" {
		t.Fatalf("expected title, got %q", got)
	}
}
