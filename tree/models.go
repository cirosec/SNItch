package tree

import (
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/scanner"
)

type FQDN struct {
	FQDN   string
	result *scanner.ScannerHostnameResult
}

type DomainLabel struct {
	Labels       map[string]*DomainLabel
	DomainPrefix string
	Hostname     *FQDN
	result       *scanner.ScannerSubdomainResult
}

type RootDomain struct {
	Labels map[string]*DomainLabel
	result *scanner.ScannerRootResult
}

// ParentNode provides access to result data from parent nodes in the domain tree.
// Both RootDomain and DomainLabel implement this interface to enable unified
// fallback comparison logic during tree printing.
type ParentNode interface {
	// HasResult returns true if the node has scan results available
	HasResult() bool
	// SNIFallbackCertificate returns the certificate serial for random subdomain requests
	SNIFallbackCertificate() string
	// HttpStatus returns the HTTP status code from the fallback scan
	HttpStatus() int
	// HttpTitle returns the HTTP page title from the fallback scan
	HttpTitle() string
	// HttpRedirect returns the HTTP redirect URL from the fallback scan
	HttpRedirect() string
}

func NewFQDN(hostname string) *FQDN {
	h := &FQDN{FQDN: hostname}
	return h
}

func NewRootDomain() *RootDomain {
	r := &RootDomain{Labels: make(map[string]*DomainLabel)}
	return r
}

func NewDomainLabel(hostname string, level int) *DomainLabel {
	a, b := helpers.GetLabelByLevelFromFQDN(hostname, level)
	prefix := a + "." + b
	if a == "" {
		prefix = b
	}
	s := &DomainLabel{DomainPrefix: prefix, Labels: make(map[string]*DomainLabel)}
	s.Hostname = NewFQDN(prefix)
	return s
}

// ParentNode interface implementation for RootDomain

func (r *RootDomain) HasResult() bool {
	return r.result != nil
}

func (r *RootDomain) SNIFallbackCertificate() string {
	if r.result == nil {
		return ""
	}
	return r.result.SNIFallbackCertificate
}

func (r *RootDomain) HttpStatus() int {
	if r.result == nil {
		return 0
	}
	return r.result.HttpStatus
}

func (r *RootDomain) HttpTitle() string {
	if r.result == nil {
		return ""
	}
	return r.result.HttpTitle
}

func (r *RootDomain) HttpRedirect() string {
	if r.result == nil {
		return ""
	}
	return r.result.HttpRedirect
}

// ParentNode interface implementation for DomainLabel

func (s *DomainLabel) HasResult() bool {
	return s.result != nil
}

func (s *DomainLabel) SNIFallbackCertificate() string {
	if s.result == nil {
		return ""
	}
	return s.result.SNIFallbackCertificate
}

func (s *DomainLabel) HttpStatus() int {
	if s.result == nil {
		return 0
	}
	return s.result.HttpStatus
}

func (s *DomainLabel) HttpTitle() string {
	if s.result == nil {
		return ""
	}
	return s.result.HttpTitle
}

func (s *DomainLabel) HttpRedirect() string {
	if s.result == nil {
		return ""
	}
	return s.result.HttpRedirect
}
