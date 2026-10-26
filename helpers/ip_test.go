package helpers

import (
	"strings"
	"testing"
)

func TestIsIPLiteral(t *testing.T) {
	yes := []string{"192.168.1.108", "127.0.0.1", "::1", "[::1]", "[0:0:0:0:0:0:0:1]", "fe80::1"}
	for _, s := range yes {
		if !IsIPLiteral(s) {
			t.Errorf("expected %q to be an IP literal", s)
		}
	}
	no := []string{"", "example.com", "synology", "host.example.invalid", "1.2.3.4.5", "999.1.1.1"}
	for _, s := range no {
		if IsIPLiteral(s) {
			t.Errorf("expected %q NOT to be an IP literal", s)
		}
	}
}

func TestCanonicalCertName(t *testing.T) {
	cases := map[string]string{
		"[::1]":           "::1",
		"0:0:0:0:0:0:0:1": "::1",
		"192.168.1.108":   "192.168.1.108",
		"example.com":     "example.com",
		"synology":        "synology",
	}
	for in, want := range cases {
		if got := CanonicalCertName(in); got != want {
			t.Errorf("CanonicalCertName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	ips, err := ExpandCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 256 {
		t.Errorf("expected 256 addresses for a /24, got %d", len(ips))
	}
	if ips[0] != "192.168.1.0" || ips[255] != "192.168.1.255" {
		t.Errorf("unexpected expansion bounds: %s .. %s", ips[0], ips[255])
	}
}

func TestExpandCIDR_ExactLimitAllowed(t *testing.T) {
	ips, err := ExpandCIDR("192.168.0.0/16")
	if err != nil {
		t.Fatalf("a /16 has 65536 addresses and must be allowed: %v", err)
	}
	if len(ips) != 65536 {
		t.Errorf("expected 65536 addresses, got %d", len(ips))
	}
}

func TestExpandCIDR_TooLarge(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/8", "0.0.0.0/0", "2001:db8::/64"} {
		ips, err := ExpandCIDR(cidr)
		if err == nil {
			t.Errorf("expected a size-guard error for %s, got %d addresses", cidr, len(ips))
			continue
		}
		if !strings.Contains(err.Error(), cidr) {
			t.Errorf("error for %s should name the CIDR: %v", cidr, err)
		}
	}
}

func TestExpandCIDR_Invalid(t *testing.T) {
	if _, err := ExpandCIDR("not/a/cidr"); err == nil {
		t.Error("expected an error for an invalid CIDR")
	}
}
