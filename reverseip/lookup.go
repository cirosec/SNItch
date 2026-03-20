package reverseip

import (
	"context"
	"fmt"
	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/helpers"
	"net"
	"strings"
	"sync"
)

type fnFilter func(string) bool

type ptrResult struct {
	ip   string
	name string
}

// LookupByTargetIPs performs PTR (reverse DNS) lookups on the provided target
// IP addresses to discover hostnames. Only the explicit scan targets are queried —
// IPs resolved from FQDNs are intentionally out of scope.
func LookupByTargetIPs(ctx context.Context, targetIPs []string, isFiltered fnFilter, debugLog *debug.DebugLogger) []string {
	ipSet := make(map[string]struct{})
	for _, ip := range targetIPs {
		if ip != "" {
			ipSet[ip] = struct{}{}
		}
	}

	// Parallel PTR lookups (IP → hostnames)
	results := make(chan ptrResult, len(ipSet)*8+1)
	var ptrWg sync.WaitGroup
	for ipStr := range ipSet {
		ptrWg.Add(1)
		go func(ip string) {
			defer ptrWg.Done()
			names, err := net.DefaultResolver.LookupAddr(ctx, ip)
			if err != nil {
				debugLog.PTRResult(ip, nil)
				return
			}
			cleaned := make([]string, 0, len(names))
			for _, name := range names {
				cleaned = append(cleaned, strings.TrimSuffix(name, "."))
			}
			debugLog.PTRResult(ip, cleaned)
			for _, name := range cleaned {
				results <- ptrResult{ip: ip, name: name}
			}
		}(ipStr)
	}
	ptrWg.Wait()
	close(results)

	// Phase 3: collect, filter, deduplicate
	discovered := []string{}
	for r := range results {
		if r.name != "" && !isFiltered(r.name) {
			discovered = append(discovered, r.name)
		}
	}
	deduped := helpers.RemoveDuplicate(discovered)
	fmt.Printf("[reverseip] Found %d hostnames via PTR lookups\n", len(deduped))
	return deduped
}
