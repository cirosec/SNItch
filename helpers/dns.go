package helpers

import (
	"strings"
)

func DNSDomainInArray(d []string, domain string) bool {
	for _, el := range d {
		if strings.HasPrefix(el, "*.") {
			if strings.HasSuffix(domain, "."+strings.Join(strings.Split(el, ".")[1:], ".")) {
				return true
			}
		}
		if el == domain {
			return true
		}
	}
	return false
}

func WildcardOrFullMatch(hostname string, matchHostList []string) bool {
	for _, ignoreEntry := range matchHostList {
		if suffix, ok := strings.CutPrefix(ignoreEntry, "*"); ok {
			if strings.HasSuffix(hostname, suffix) {
				return true
			}
			// Also match the base domain (e.g., *.example.com should match example.com)
			// Technically it should not do that but for laziness this is fine
			if suffix[0] == '.' && hostname == suffix[1:] {
				return true
			}
		}
		if hostname == ignoreEntry {
			return true
		}
	}
	return false
}
