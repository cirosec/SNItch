package tree

import (
	"fmt"
	"strings"

	"github.com/cirosec/snitch/helpers"
)

func (r *RootDomain) DebugPrint(target string) {
	fmt.Printf("[RootDomain] %s", target)
	if r.result != nil {
		fmt.Printf("  fallback_cert=%s http=%d", r.result.SNIFallbackCertificate, r.result.HttpStatus)
	}
	fmt.Println()

	keys := make([]string, 0, len(r.Labels))
	for k := range r.Labels {
		keys = append(keys, k)
	}
	helpers.SortDomains(keys)

	for i, key := range keys {
		isLast := i == len(keys)-1
		r.Labels[key].debugPrint("", isLast)
	}
}

func (s *DomainLabel) debugPrint(prefix string, last bool) {
	connector := "├── "
	childPrefix := prefix + "│   "
	if last {
		connector = "└── "
		childPrefix = prefix + "    "
	}

	fmt.Printf("%s%s%s", prefix, connector, s.DomainPrefix)
	if s.result != nil {
		fmt.Printf("  [wildcard] fallback_cert=%s http=%d", s.result.SNIFallbackCertificate, s.result.HttpStatus)
	}
	fmt.Println()

	if s.Hostname != nil && s.Hostname.result != nil {
		h := s.Hostname
		hasChildren := len(s.Labels) > 0
		hConn := "└── "
		if hasChildren {
			hConn = "├── "
		}
		fmt.Printf("%s%s[FQDN] %s  cert=%s http=%d", childPrefix, hConn, h.FQDN, h.result.Certificate, h.result.HttpStatus)
		if h.result.HttpTitle != "" {
			fmt.Printf(" title=%q", h.result.HttpTitle)
		}
		if h.result.HttpRedirect != "" {
			fmt.Printf(" redirect=%s", h.result.HttpRedirect)
		}
		fmt.Println()
	}

	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		keys = append(keys, k)
	}
	helpers.SortDomains(keys)

	for i, key := range keys {
		isLast := i == len(keys)-1
		s.Labels[key].debugPrint(childPrefix, isLast)
	}
}

func ForestDebugPrint(forest map[string]*RootDomain) {
	targets := make([]string, 0, len(forest))
	for t := range forest {
		targets = append(targets, t)
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("TREE DEBUG VIEW")
	fmt.Println(strings.Repeat("=", 60))
	for _, target := range targets {
		forest[target].DebugPrint(target)
		fmt.Println(strings.Repeat("-", 60))
	}
}
