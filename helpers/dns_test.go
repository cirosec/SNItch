package helpers

import "testing"

func TestDNS(t *testing.T) {
	if !DNSDomainInArray([]string{"*.cirosec.de", "cirosec.de"}, "someapp.cirosec.de") {
		t.Fail()
	}
}

func TestDNSDomainInArray(t *testing.T) {
	tests := []struct {
		entries []string
		domain  string
		want    bool
	}{
		{[]string{"www.example.com"}, "www.example.com", true},
		{[]string{"www.example.com"}, "www.example.com.", true},
		{[]string{"www.example.com."}, "www.example.com", true},
		{[]string{"WWW.Example.COM"}, "www.example.com", true},
		{[]string{"*.example.com"}, "foo.example.com", true},
		{[]string{"*.example.com"}, "a.b.example.com", false},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"*.EXAMPLE.com."}, "foo.example.com", true},
		{[]string{"*.example.com"}, "fooexample.com", false},
		{[]string{"example.com"}, "www.example.com", false},
	}
	for _, tt := range tests {
		if got := DNSDomainInArray(tt.entries, tt.domain); got != tt.want {
			t.Errorf("DNSDomainInArray(%v, %q) = %v, want %v", tt.entries, tt.domain, got, tt.want)
		}
	}
}

func TestWildcardOrFullMatch(t *testing.T) {
	tests := []struct {
		hostname string
		list    []string
		want    bool
	}{
		{"foo.example.com", []string{"*.example.com"}, true},
		{"a.b.example.com", []string{"*.example.com"}, true},
		{"example.com", []string{"*.example.com"}, true},
		{"FOO.Example.COM", []string{"*.example.com"}, true},
		{"foo.example.com.", []string{"*.example.com."}, true},
		{"foo.example.com", []string{"*.EXAMPLE.com"}, true},
		{"foo.example.com", []string{"foo.example.com"}, true},
		{"foo.example.com", []string{"FOO.EXAMPLE.COM"}, true},
		{"notexample.com", []string{"*example.com"}, false},
		{"foo.example.com", []string{"*example.com"}, false},
		{"anything.example.org", []string{"*"}, false},
		{"foo.example.com", []string{"*.other.com"}, false},
	}
	for _, tt := range tests {
		if got := WildcardOrFullMatch(tt.hostname, tt.list); got != tt.want {
			t.Errorf("WildcardOrFullMatch(%q, %v) = %v, want %v", tt.hostname, tt.list, got, tt.want)
		}
	}
}