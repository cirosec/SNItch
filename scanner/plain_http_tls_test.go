package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
)

// newRootResultForTarget builds a ScannerRootResult whose target points at a
// test server, so checkPlainHTTPTLS probes that server's port.
func newRootResultForTarget(t *testing.T, target string) *ScannerRootResult {
	t.Helper()
	resolver := dns.NewDNSResolver("")
	t.Cleanup(resolver.Stop)
	gctx := globalcontext.NewGlobalContext(resolver)
	gctx.DebugLog = debug.NopLogger()
	gctx.Timeout = 5 * time.Second
	return NewScannerRootResult(target, gctx, true, false, "80")
}

// A plaintext-HTTP response on the target's TLS port that redirects to a real
// domain must be recorded as an (HTTP/TLS) row and fed back into recon.
func TestCheckPlainHTTPTLS_RevealsLeakFromRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://leak.internal.example/login")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	target := strings.TrimPrefix(srv.URL, "http://")
	s := newRootResultForTarget(t, target)
	s.checkPlainHTTPTLS(context.Background())

	if s.PlainHTTPTLSStatus != http.StatusMovedPermanently {
		t.Fatalf("expected (HTTP/TLS) result with 301, got status %d", s.PlainHTTPTLSStatus)
	}
	if !strings.Contains(s.PlainHTTPTLSRedirect, "leak.internal.example") {
		t.Fatalf("unexpected redirect %q", s.PlainHTTPTLSRedirect)
	}
	redirects := s.gctx.RedirectHostnames()
	if len(redirects) != 1 || redirects[0] != "leak.internal.example" {
		t.Fatalf("expected leak.internal.example queued, got %v", redirects)
	}
}

// The standard plaintext rejection (nginx/Caddy answer "400 The plain HTTP
// request was sent to HTTPS port") reveals no hostname and must not create a row.
func TestCheckPlainHTTPTLS_NoRevealOnPlainRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<html><head><title>400 The plain HTTP request was sent to HTTPS port</title></head></html>"))
	}))
	defer srv.Close()

	target := strings.TrimPrefix(srv.URL, "http://")
	s := newRootResultForTarget(t, target)
	s.checkPlainHTTPTLS(context.Background())

	if s.PlainHTTPTLSStatus != 0 {
		t.Fatalf("expected no (HTTP/TLS) row for a benign 400, got status %d", s.PlainHTTPTLSStatus)
	}
	if len(s.gctx.RedirectHostnames()) != 0 {
		t.Fatalf("benign 400 must not queue redirects, got %v", s.gctx.RedirectHostnames())
	}
}

// When the target's port is the same as the configured HTTP port the TLS probe
// would only repeat the plain-HTTP probe and must be skipped.
func TestCheckPlainHTTPTLS_SkipsConfiguredHTTPPort(t *testing.T) {
	s := newRootResultForTarget(t, "127.0.0.1:80")
	s.httpPort = "80"
	s.checkPlainHTTPTLS(context.Background())
	if s.PlainHTTPTLSStatus != 0 {
		t.Fatalf("expected no probe when the target port equals the HTTP port, got status %d", s.PlainHTTPTLSStatus)
	}
}

func TestTargetPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:443":       "443",
		"example.com:8443":  "8443",
		"[2001:db8::1]:443": "443",
		"example.com":       "",
	}
	for in, want := range cases {
		if got := targetPort(in); got != want {
			t.Fatalf("targetPort(%q) = %q, want %q", in, got, want)
		}
	}
}
