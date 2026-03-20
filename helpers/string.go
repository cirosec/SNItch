package helpers

import (
	"bytes"
	"net"
	"sort"
	"strings"
)

func CenterString(str string, width int, symbol string) string {
	spaces := int(float64(width-len(str)) / 2)
	return strings.Repeat(symbol, spaces) + str + strings.Repeat(symbol, width-(spaces+len(str)))
}

func SortDomains(domains []string) {
	sort.Slice(domains, func(i, j int) bool {
		// Split the domain strings into subdomains and domain
		subdomainsA := strings.Split(domains[i], ".")
		subdomainsB := strings.Split(domains[j], ".")

		// Compare subdomains in reverse order
		for k := 1; k <= len(subdomainsA) && k <= len(subdomainsB); k++ {
			indexA := len(subdomainsA) - k
			indexB := len(subdomainsB) - k

			if subdomainsA[indexA] != subdomainsB[indexB] {
				return subdomainsA[indexA] < subdomainsB[indexB]
			}
		}

		// If subdomains are the same, compare main domains
		return domains[i] < domains[j]
	})
}

func SortIPAddresses(ipAddresses []string) []string {
	sort.Slice(ipAddresses, func(i, j int) bool {
		h1, p1, err1 := net.SplitHostPort(ipAddresses[i])
		if err1 != nil && err1.(*net.AddrError).Err == "missing port in address" {
			p1 = "0"
			h1 = ipAddresses[i]
		}
		h2, p2, err2 := net.SplitHostPort(ipAddresses[j])
		if err2 != nil && err2.(*net.AddrError).Err == "missing port in address" {
			p2 = "0"
			h2 = ipAddresses[j]
		}
		r := bytes.Compare(net.ParseIP(h1), net.ParseIP(h2))
		if r == 0 {
			return p1 < p2
		}
		return r < 0
	})
	return ipAddresses
}
