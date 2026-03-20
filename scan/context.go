package scan

import (
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/models"
	"sync"
)

type ScanContext struct {
	hostsLock  sync.Mutex
	hosts      map[string]bool //map of the hostnames and wildcards. The bool encodes if this hostname has been scanned.
	targets    []string
	resultLock sync.Mutex
	results    map[models.ScanContextResultKey]interface{}
	config     *ScanConfig
}

func NewScanContext(config *ScanConfig) *ScanContext {
	s := &ScanContext{hostsLock: sync.Mutex{}, config: config, resultLock: sync.Mutex{}, targets: []string{}, results: map[models.ScanContextResultKey]interface{}{}, hosts: map[string]bool{}}
	s.hosts["."] = false // The target root. Is required to trigger a general scan of the target. It's position in the DNS-label-tree is described in the DNS RFC.
	return s
}

func (h *ScanContext) AddResult(target string, host string, result interface{}) {
	h.resultLock.Lock()
	defer h.resultLock.Unlock()
	h.results[models.ScanContextResultKey{Target: target, Host: host}] = result
}

func (h *ScanContext) GetHosts() []string {
	// Returns a list of all hosts in the current scan iteration
	h.hostsLock.Lock()
	defer h.hostsLock.Unlock()
	keys := make([]string, len(h.hosts)-1)
	i := 0
	for k := range h.hosts {
		if k == "." {
			continue
		}
		keys[i] = k
		i++
	}
	return keys
}

func (h *ScanContext) GetUnscannedHosts() []string {
	// Returns hosts, which have not been scanned yet
	h.hostsLock.Lock()
	defer h.hostsLock.Unlock()
	keys := []string{}
	for k, v := range h.hosts {
		if !v {
			keys = append(keys, k)
		}
	}
	return keys
}

func (h *ScanContext) FlagAllHosts() {
	// Mark all hosts as scanned
	h.hostsLock.Lock()
	defer h.hostsLock.Unlock()
	for key := range h.hosts {
		h.hosts[key] = true
	}
}

func (h *ScanContext) AddTarget(target string) {
	if !helpers.Contains(h.targets, target) {
		h.targets = append(h.targets, target)
	}
}

func (h *ScanContext) GetTargets() []string {
	return h.targets
}

func (h *ScanContext) isIgnoredFQDN(fqdn string) bool {
	return helpers.WildcardOrFullMatch(fqdn, h.config.AllIgnoredHosts())
}

func (h *ScanContext) AddFQDN(fqdn string) {
	if h.isIgnoredFQDN(fqdn) {
		return
	}
	sld, err := helpers.FQDNToSLD(fqdn)
	if err != nil {
		return
	}
	h.hostsLock.Lock()
	defer h.hostsLock.Unlock()

	// Add SLD to host list
	if ok := h.hosts[sld]; !ok {
		h.hosts[sld] = false
	}

	//Add wildcard to hosts list
	if ok := h.hosts["*."+sld]; !ok {
		h.hosts["*."+sld] = false
	}

	if fqdn == sld {
		// Nothing more must be done if the input was a valid SLD
		return
	}
	level := 2
	for {
		label, right_labels := helpers.GetLabelByLevelFromFQDN(fqdn, level)
		level += 1
		if label == "*" { //When the host is a wildcard. Add it!
			if ok := h.hosts["*."+right_labels]; !ok {
				h.hosts["*."+right_labels] = false
			}
			break
		}
		if label == "" { //No more domain
			if ok := h.hosts[right_labels]; !ok {
				h.hosts[right_labels] = false
			}
			break
		} else {
			// If there is a level aka. a valid subdomain
			if ok := h.hosts[right_labels]; !ok {
				h.hosts[right_labels] = false
			}
			if ok := h.hosts["*."+right_labels]; !ok {
				h.hosts["*."+right_labels] = false
			}
		}
	}
}
