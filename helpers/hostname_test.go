package helpers

import (
	"strings"
	"testing"
)

func TestIsValidHostname_Accept(t *testing.T) {
	valid := []string{
		"synology",
		"localhost",
		"sp7364.dyndns.org",
		"host.example.invalid",
		"*.example.com",
		"a-b.c-d.example",
		"host.example.com.",
		"_dmarc.example.com",
		"exa_mple.com",
		strings.Repeat("a", 63) + ".example.com",
	}
	for _, name := range valid {
		if !IsValidHostname(name) {
			t.Errorf("expected %q to be a valid hostname", name)
		}
	}
}

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"  example.com ", "example.com", true},
		{"host.example.com.", "host.example.com", true},
		{"Host.Example.COM", "host.example.com", true},
		{"*.Example.COM.", "*.example.com", true},
		{"bücher.example.com", "xn--bcher-kva.example.com", true},
		{"_dmarc.example.com", "_dmarc.example.com", true},
		{"   ", "", false},
		{"*. invalid.name", "", false},
		{"host example.com", "", false},
	}
	for _, tt := range tests {
		got, ok := SanitizeHostname(tt.in)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("SanitizeHostname(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestCanonicalHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"  Example.COM.  ", "example.com", true},
		{"WWW.example.com.", "www.example.com", true},
		{"*.Foo.Bar.", "*.foo.bar", true},
		{"bücher.example.com", "xn--bcher-kva.example.com", true},
		{"_dmarc.example.com", "_dmarc.example.com", true},
		{"xn--bcher-kva.example.com", "xn--bcher-kva.example.com", true},
		{"", "", false},
		{".", "", false},
		{"not a hostname!", "", false},
		{"*", "", false},
		{"a..b", "", false},
		{"-bad.example.com", "", false},
	}
	for _, tt := range tests {
		got, ok := CanonicalHostname(tt.in)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("CanonicalHostname(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestIsValidHostname_Reject(t *testing.T) {
	invalid := []string{
		"",
		".",
		"-bad.example.com",
		"bad-.example.com",
		"a..b",
		"white space.com",
		"*.example.com*",
		strings.Repeat("a", 64) + ".com",
	}
	for _, name := range invalid {
		if IsValidHostname(name) {
			t.Errorf("expected %q to be rejected", name)
		}
	}
}