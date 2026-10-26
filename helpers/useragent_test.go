package helpers

import (
	"net/http"
	"strings"
	"testing"
)

func TestResolveUserAgent(t *testing.T) {
	if got := ResolveUserAgent(""); got != DefaultUserAgent {
		t.Fatalf("expected default UA, got %q", got)
	}
	if got := ResolveUserAgent("custom/1.0"); got != "custom/1.0" {
		t.Fatalf("expected custom UA, got %q", got)
	}
}

func TestSetUserAgentAlwaysSetsNonGoDefault(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	SetUserAgent(req, "")
	if got := req.Header.Get("User-Agent"); got == "" || got == "Go-http-client/1.1" {
		t.Fatalf("expected non-Go default UA, got %q", got)
	}
	SetUserAgent(req, "custom/2.0")
	if got := req.Header.Get("User-Agent"); got != "custom/2.0" {
		t.Fatalf("expected custom UA, got %q", got)
	}
}

func TestDefaultUserAgentIsGeneric(t *testing.T) {
	if strings.Contains(DefaultUserAgent, "Go-http-client") {
		t.Fatalf("default UA must not be the Go fingerprint: %q", DefaultUserAgent)
	}
}
