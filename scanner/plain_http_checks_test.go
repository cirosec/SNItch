package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
)

func newTestRootResult(t *testing.T, httpPort string) *ScannerRootResult {
	t.Helper()
	resolver := dns.NewDNSResolver("")
	t.Cleanup(resolver.Stop)
	gctx := globalcontext.NewGlobalContext(resolver)
	gctx.DebugLog = debug.NopLogger()
	gctx.Timeout = 5 * time.Second
	return NewScannerRootResult("127.0.0.1:443", gctx, true, false, httpPort)
}

func servePort(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// A bare 404 (or any response without a revealed domain) must not produce a row.
func TestCheckPlainHTTP_NoRevealOnPlainResponse(t *testing.T) {
	port := servePort(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	s := newTestRootResult(t, port)
	s.checkPlainHTTP(context.Background())
	if s.PlainHTTPStatus != 0 {
		t.Fatalf("expected no (HTTP) result for plain 404, got status %d", s.PlainHTTPStatus)
	}
}

// Redirecting to https://<ip>/ is just a scheme upgrade with no new domain.
func TestCheckPlainHTTP_NoRevealOnIPRedirect(t *testing.T) {
	port := servePort(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://127.0.0.1/")
		w.WriteHeader(http.StatusPermanentRedirect)
	})
	s := newTestRootResult(t, port)
	s.checkPlainHTTP(context.Background())
	if s.PlainHTTPStatus != 0 {
		t.Fatalf("expected no (HTTP) result for IP-only redirect, got status %d", s.PlainHTTPStatus)
	}
	if len(s.gctx.RedirectHostnames()) != 0 {
		t.Fatalf("IP-only redirect must not be queued, got %v", s.gctx.RedirectHostnames())
	}
}

// A redirect that leaks a real domain must produce a row and feed recon.
func TestCheckPlainHTTP_RevealOnDomainRedirect(t *testing.T) {
	port := servePort(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://real.internal.example/login")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	s := newTestRootResult(t, port)
	s.checkPlainHTTP(context.Background())
	if s.PlainHTTPStatus != http.StatusMovedPermanently {
		t.Fatalf("expected (HTTP) result with 301, got status %d", s.PlainHTTPStatus)
	}
	redirects := s.gctx.RedirectHostnames()
	if len(redirects) != 1 || redirects[0] != "real.internal.example" {
		t.Fatalf("expected real.internal.example queued, got %v", redirects)
	}
}

// The random-host variant that triggers a reveal must be flagged so its row can
// be labeled "(HTTP random)" instead of echoing an ephemeral, meaningless domain.
func TestCheckPlainHTTP_FlagsRandomVariant(t *testing.T) {
	port := servePort(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Host, ".com") {
			w.Header().Set("Location", "https://real.internal.example/login")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s := newTestRootResult(t, port)
	s.checkPlainHTTP(context.Background())
	if s.PlainHTTPStatus != http.StatusMovedPermanently {
		t.Fatalf("expected (HTTP) result with 301, got status %d", s.PlainHTTPStatus)
	}
	if !s.PlainHTTPHostRandom {
		t.Fatalf("expected the random variant to be flagged, host=%q", s.PlainHTTPHost)
	}
}

// The Host-less HTTP/1.0 variant covers the self-referential-redirect fallback:
// a server that redirects only when no host information is present (echoing
// its configured server name) must be flagged so the row can be labeled
// "(HTTP no-host)" and the configured name must be fed back into recon.
func TestCheckPlainHTTP_NoHostFallbackReveal(t *testing.T) {
	port := servePort(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" {
			// nginx absolute_redirect-style fallback: no host in the request,
			// so the redirect is built from the configured server name.
			w.Header().Set("Location", "https://canonical.example/")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s := newTestRootResult(t, port)
	s.checkPlainHTTP(context.Background())
	if s.PlainHTTPStatus != http.StatusMovedPermanently {
		t.Fatalf("expected (HTTP) result with 301, got status %d", s.PlainHTTPStatus)
	}
	if !s.PlainHTTPHostNoHost {
		t.Fatalf("expected the no-host variant to be flagged, host=%q", s.PlainHTTPHost)
	}
	redirects := s.gctx.RedirectHostnames()
	if len(redirects) != 1 || redirects[0] != "canonical.example" {
		t.Fatalf("expected canonical.example queued, got %v", redirects)
	}
}
