package helpers

import (
	"strings"
)

// DNSDomainInArray reports whether domain is covered by any entry in d.
// Matching is case-insensitive and ignores trailing dots. A wildcard entry
// ("*.example.com") covers exactly one label (RFC 6125): it matches
// "foo.example.com" but neither "a.b.example.com" nor "example.com".
func DNSDomainInArray(d []string, domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	for _, el := range d {
		el = strings.TrimSuffix(el, ".")
		if base, ok := strings.CutPrefix(el, "*."); ok {
			if wildcardCoversOneLabel(base, domain) {
				return true
			}
			continue
		}
		if strings.EqualFold(el, domain) {
			return true
		}
	}
	return false
}

func wildcardCoversOneLabel(wildcardBase, domain string) bool {
	dParts := strings.Split(domain, ".")
	bParts := strings.Split(wildcardBase, ".")
	if len(dParts) != len(bParts)+1 {
		return false
	}
	return strings.EqualFold(strings.Join(dParts[1:], "."), wildcardBase)
}

// WildcardOrFullMatch reports whether hostname is covered by an ignore-style
// match list. Entries are compared case-insensitively and without trailing
// dots. A "*.<domain>" entry matches the domain itself and every subdomain
// below it. A wildcard suffix without a label boundary ("*example.com") never
// matches, and a bare "*" matches nothing: use an explicit domain instead.
func WildcardOrFullMatch(hostname string, matchHostList []string) bool {
	hostname = strings.TrimSuffix(hostname, ".")
	for _, ignoreEntry := range matchHostList {
		entry := strings.TrimSuffix(ignoreEntry, ".")
		if suffix, ok := strings.CutPrefix(entry, "*"); ok && strings.HasPrefix(suffix, ".") {
			if hasSuffixFold(hostname, suffix) {
				return true
			}
			// Also match the base domain (e.g., *.example.com matches example.com)
			if strings.EqualFold(hostname, suffix[1:]) {
				return true
			}
			continue
		}
		if strings.EqualFold(hostname, entry) {
			return true
		}
	}
	return false
}

func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}