package whois

import (
	"context"
	"fmt"
	"github.com/cirosec/snitch/helpers"
	"net"
	"regexp"
	"sort"
	"sync"

	"github.com/fatih/color"
	"github.com/likexian/whois"
)

type WHOISinfo struct {
	Name  string
	Range string
}

type WHOISCache struct {
	mutex sync.RWMutex
	cache map[string]*WHOISinfo
}

func NewWHOISCache() *WHOISCache {
	return &WHOISCache{cache: make(map[string]*WHOISinfo)}
}

func (w *WHOISCache) Query(ctx context.Context, IPs []string) {
	newIPs := []string{}
	w.mutex.Lock()
	for _, ip := range IPs {
		if val, ok := w.cache[ip]; !ok || val == nil {
			newIPs = append(newIPs, ip)
		}
	}
	w.mutex.Unlock()
	for _, ip := range newIPs {
		if ctx.Err() != nil {
			return
		}
		result := QueryWHOIS(ip)
		w.mutex.Lock()
		w.cache[ip] = result
		w.mutex.Unlock()
	}
}

func (w *WHOISCache) Get(ip string) *WHOISinfo {
	w.mutex.Lock()
	if val, ok := w.cache[ip]; ok {
		w.mutex.Unlock()
		return val
	} else {
		w.mutex.Unlock()
	}
	record := QueryWHOIS(ip)
	w.mutex.Lock()
	w.cache[ip] = record
	w.mutex.Unlock()
	return record
}

func QueryWHOIS(ip string) *WHOISinfo {
	rawResult, err := whois.Whois(ip)
	if err != nil {
		return nil
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
	return &WHOISinfo{Name: name, Range: netrange}
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
