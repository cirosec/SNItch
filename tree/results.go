package tree

import (
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/scanner"
	"strings"
)

func (s *DomainLabel) AddResult(hostname string, level int, result interface{}) bool {
	if hostname == s.Hostname.FQDN {
		//fmt.Printf("(FQDN) Added result to %s\n", hostname)
		if hostnameResult, ok := result.(*scanner.ScannerHostnameResult); ok {
			s.Hostname.result = hostnameResult
		}
		return true
	}
	if !strings.HasSuffix(hostname, "."+s.DomainPrefix) {
		return false
	}
	if "*."+s.DomainPrefix == hostname {
		//fmt.Printf("(Wildcard) Added result to %s\n", hostname)
		if subdomainResult, ok := result.(*scanner.ScannerSubdomainResult); ok {
			s.result = subdomainResult
		}
		return true
	}
	label, suffix := helpers.GetLabelByLevelFromFQDN(hostname, level+1)
	var sd *DomainLabel
	if val, ok := s.Labels[label+"."+suffix]; ok {
		sd = val
	} else {
		sd = NewDomainLabel(hostname, level+1)
		s.Labels[label+"."+suffix] = sd
	}
	return sd.AddResult(hostname, level+1, result)
}

func (r *RootDomain) AddResult(hostname string, result interface{}) {
	if hostname == "." {
		if rootResult, ok := result.(*scanner.ScannerRootResult); ok {
			r.result = rootResult
		}
		return
	}
	_, Domain := helpers.GetLabelByLevelFromFQDN(hostname, 0)
	if len(Domain) == 0 {
		return
	}
	var label *DomainLabel
	if val, ok := r.Labels[Domain]; ok {
		label = val
	} else {
		label = NewDomainLabel(hostname, 0)
		r.Labels[Domain] = label
	}
	label.AddResult(hostname, 0, result)
}
