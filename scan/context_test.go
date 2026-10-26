package scan

import (
	"strings"
	"testing"
)

// A syntactically valid hostname without a known public suffix (single label,
// internal name) must still be queued for scanning.
func TestAddFQDN_AcceptsValidHostnameWithoutPublicSuffix(t *testing.T) {
	c := NewScanContext(NewConfig())

	for _, host := range []string{"synology", "host.corp.local"} {
		c.AddFQDN(host)
		if _, ok := c.hosts[host]; !ok {
			t.Errorf("expected %q to be queued", host)
		}
	}
}

// IP literals, including bracketed IPv6, are addresses and must never be
// queued as hostnames.
func TestAddFQDN_RejectsIPLiterals(t *testing.T) {
	c := NewScanContext(NewConfig())

	for _, host := range []string{"192.168.1.108", "127.0.0.1", "::1", "[::1]"} {
		c.AddFQDN(host)
		if _, ok := c.hosts[host]; ok {
			t.Errorf("IP literal %q must not be queued", host)
		}
	}
}

func TestAddFQDN_RejectsInvalidHostname(t *testing.T) {
	c := NewScanContext(NewConfig())

	c.AddFQDN("not a hostname!")
	if _, ok := c.hosts["not a hostname!"]; ok {
		t.Fatal("invalid hostname must not be queued")
	}
}

// Case and trailing-dot variants of the same name must canonicalize to one
// set of queue entries instead of splitting the scan across two twins.
func TestAddFQDN_CanonicalizesCaseAndTrailingDot(t *testing.T) {
	c := NewScanContext(NewConfig())
	c.AddFQDN("Host.Example.COM.")
	c.AddFQDN("host.example.com")

	found := 0
	for _, host := range c.GetHosts() {
		if host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
			t.Errorf("non-canonical host %q in queue", host)
		}
		if strings.Contains(host, "example.com") {
			found++
		}
	}
	if found != 3 {
		t.Errorf("expected 3 canonical example.com entries (sld, wildcard, host), got %d: %v", found, c.GetHosts())
	}
}
