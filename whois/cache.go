package whois

import (
	"context"
	"fmt"
	"github.com/cirosec/snitch/helpers"
	"net"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/likexian/whois"
)

// whoisQueryTimeout bounds each WHOIS query. likexian/whois has no context
// support, so the query runs in a goroutine and is abandoned on timeout.
const whoisQueryTimeout = 10 * time.Second

type WHOISinfo struct {
	Name  string
	Range string
}

type WHOISCache struct {
	mutex sync.RWMutex
	cache map[string]*WHOISinfo
	failed map[string]bool
	query func(ip string, timeout time.Duration) (*WHOISinfo, error)
}

func NewWHOISCache() *WHOISCache {
	return &WHOISCache{cache: make(map[string]*WHOISinfo), failed: make(map[string]bool), query: QueryWHOIS}
}

// SetQueryFunc overrides the underlying WHOIS query implementation. It is
// intended for tests so scans can run without touching real WHOIS servers.
func (w *WHOISCache) SetQueryFunc(fn func(ip string, timeout time.Duration) (*WHOISinfo, error)) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.query = fn
}

// queryLocked records the lookup result for ip so each IP is queried at most
// once per run. The caller must hold the mutex.
func (w *WHOISCache) queryLocked(ip string) *WHOISinfo {
	result, err := w.query(ip, whoisQueryTimeout)
	if err != nil {
		w.failed[ip] = true
		return nil
	}
	w.cache[ip] = result
	return result
}

func (w *WHOISCache) Query(ctx context.Context, IPs []string) {
	newIPs := []string{}
	w.mutex.Lock()
	for _, ip := range IPs {
		if _, ok := w.cache[ip]; ok {
			continue
		}
		if w.failed[ip] {
			continue
		}
		newIPs = append(newIPs, ip)
	}
	w.mutex.Unlock()
	for _, ip := range newIPs {
		if ctx.Err() != nil {
			return
		}
		w.mutex.Lock()
		if _, ok := w.cache[ip]; !ok && !w.failed[ip] {
			w.queryLocked(ip)
		}
		w.mutex.Unlock()
	}
}

func (w *WHOISCache) Get(ip string) *WHOISinfo {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if val, ok := w.cache[ip]; ok {
		return val
	}
	if w.failed[ip] {
		return nil
	}
	return w.queryLocked(ip)
}

func QueryWHOIS(ip string, timeout time.Duration) (*WHOISinfo, error) {
	type whoisResult struct {
		raw string
		err error
	}
	ch := make(chan whoisResult, 1)
	go func() {
		rawResult, err := whois.Whois(ip)
		ch <- whoisResult{raw: rawResult, err: err}
	}()
	var rawResult string
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		rawResult = r.raw
	case <-time.After(timeout):
		return nil, fmt.Errorf("whois query for %s timed out after %s", ip, timeout)
	}
	netrange := ""
	pattern := regexp.MustCompile(`inetnum:\s*(.+)`)
	match := pattern.FindStringSubmatch(rawResult)
	if len(match) > 1 {
		netrange = match[1]
	}
	name := ""
	pattern = regexp.MustCompile(`netname:\s*(.+)`)
	match = pattern.FindStringSubmatch(rawResult)
	if len(match) > 1 {
		name = match[1]
	}
	if name == "" {
		pattern = regexp.MustCompile(`Organization:\s*(.+)`)
		match = pattern.FindStringSubmatch(rawResult)
		if len(match) > 1 {
			name = match[1]
		}
	}
	return &WHOISinfo{Name: name, Range: netrange}, nil
}

func (w *WHOISCache) Print(targetIPs []string) {
	fmt.Print("\n")
	fmt.Println(helpers.CenterString(" Observed IPs ", 50, "─"))

	newTargets := []string{}
	for _, t := range targetIPs {
		ip, _, _ := net.SplitHostPort(t)
		newTargets = append(newTargets, ip)
	}

	sortedIPs := helpers.RemoveDuplicate(newTargets)

	grouped := map[string][]string{}
	for _, ip := range sortedIPs {
		wI := w.Get(ip)
		name := "(UNKNOWN)"
		if wI != nil {
			sRange := ""
			if wI.Range != "" {
				sRange = fmt.Sprintf("(%s)", wI.Range)
			}
			name = fmt.Sprintf("%s %s", wI.Name, sRange)
		}
		if _, ok := grouped[name]; !ok {
			grouped[name] = []string{}
		}
		grouped[name] = append(grouped[name], ip)
	}

	blockColor := color.New(color.FgBlack, color.BgWhite).SprintFunc()

	groupKeys := make([]string, 0, len(grouped))
	for k := range grouped {
		groupKeys = append(groupKeys, k)
	}

	sort.Strings(groupKeys)

	for _, k := range groupKeys {
		fmt.Printf("%s\n", blockColor(k))
		fmt.Printf("⤷ %s\n", ColoredIPHelper(grouped[k], newTargets))
	}

}

func ColoredIPHelper(ipsToPrint []string, targetIPs []string) string {
	r := ""
	for i, ip := range ipsToPrint {
		if helpers.Contains(targetIPs, ip) {
			r += color.BlueString(ip)
		} else {
			r += ip
		}
		if i != len(ipsToPrint)-1 {
			r += ", "
		}
	}
	return r
}
