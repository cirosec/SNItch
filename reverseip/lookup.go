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

type addrLookup func(ctx context.Context, addr string) ([]string, error)

type ptrResult struct {
	ip   string
	name string
}

// LookupByTargetIPs performs PTR (reverse DNS) lookups on the provided target
// IP addresses to discover hostnames. Only the explicit scan targets are queried —
// IPs resolved from FQDNs are intentionally out of scope.
func LookupByTargetIPs(ctx context.Context, targetIPs []string, isFiltered fnFilter, debugLog *debug.DebugLogger) []string {
	return collectPTRs(ctx, targetIPs, net.DefaultResolver.LookupAddr, isFiltered, debugLog)
}

// collectPTRs queries one lookup per unique IP and returns the filtered,
// deduplicated hostnames. The results channel is drained by a dedicated
// collector goroutine so producers can never block on send, no matter how
// many names an IP yields.
func collectPTRs(ctx context.Context, targetIPs []string, lookup addrLookup, isFiltered fnFilter, debugLog *debug.DebugLogger) []string {
	ipSet := make(map[string]struct{})
	for _, ip := range targetIPs {
		if ip != "" {
			ipSet[ip] = struct{}{}
		}
	}

	// Parallel PTR lookups (IP → hostnames)
	results := make(chan ptrResult)
	var ptrWg sync.WaitGroup
	for ipStr := range ipSet {
		ptrWg.Add(1)
		go func(ip string) {
			defer ptrWg.Done()
			names, err := lookup(ctx, ip)
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

	discovered := []string{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range results {
			if r.name != "" && !isFiltered(r.name) {
				discovered = append(discovered, r.name)
			}
		}
	}()
	ptrWg.Wait()
	close(results)
	<-done

	deduped := helpers.RemoveDuplicate(discovered)
	fmt.Printf("[reverseip] Found %d hostnames via PTR lookups\n", len(deduped))
	return deduped
}
