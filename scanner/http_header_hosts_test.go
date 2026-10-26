package scanner

import (
	"net/http"
	"testing"

	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
)

func newHeaderHostContext(t *testing.T) *globalcontext.GlobalContext {
	t.Helper()
	g := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	t.Cleanup(func() { g.DNSresolver.Stop() })
	g.SearchHeaders = true
	return g
}

func headerResponse(setCookies ...string) *http.Response {
	resp := &http.Response{Header: make(http.Header)}
	for _, c := range setCookies {
		resp.Header.Add("Set-Cookie", c)
	}
	return resp
}

func TestExtractHeaderHosts_CookieDomainAttribute(t *testing.T) {
	g := newHeaderHostContext(t)

	resp := headerResponse(
		"sess=abc123; Domain=.real-shop.example.com; Path=/; Secure; HttpOnly",
		"tracker=xyz; domain=CDN.Vendor-Net.example; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
	)
	found := extractHeaderHosts(resp, g, "")
	if len(found) != 2 {
		t.Fatalf("expected 2 cookie domains, got %v", found)
	}
	for _, want := range []string{"real-shop.example.com", "cdn.vendor-net.example"} {
		if !containsString(found, want) {
			t.Fatalf("expected cookie domain %q, got %v", want, found)
		}
		if !containsString(g.HeaderHostnames(), want) {
			t.Fatalf("expected %q to be queued in the global context, got %v", want, g.HeaderHostnames())
		}
	}
}

func TestExtractHeaderHosts_CookieDomainFilters(t *testing.T) {
	g := newHeaderHostContext(t)

	resp := headerResponse(
		"a=1",                          // no Domain attribute
		"b=2; Path=/; Secure",          // attributes only, no Domain
		"c=3; Domain=192.168.1.10",     // IP literal: not a hostname
		"d=4; Domain="+randHost+".com", // echoes the random probe host: reflection, not a discovery
		"e=5; Domain=.first-wins.example.org; Domain=last-wins.example.com", // RFC 6265 §5.2: last Domain attribute wins
	)
	found := extractHeaderHosts(resp, g, randHost)
	if len(found) != 1 || found[0] != "last-wins.example.com" {
		t.Fatalf("expected only last-wins.example.com to survive the filters, got %v", found)
	}
}

func TestExtractHeaderHosts_SearchHeadersDisabled(t *testing.T) {
	g := newHeaderHostContext(t)
	g.SearchHeaders = false

	found := extractHeaderHosts(headerResponse("sess=abc; Domain=.example.com"), g, "")
	if len(found) != 0 {
		t.Fatalf("expected no extraction with SearchHeaders disabled, got %v", found)
	}
}

const randHost = "qwzxbnmcde"

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
