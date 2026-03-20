package globalcontext

import (
	"crypto/x509"
	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/whois"
	"sync"
	"time"
)

type GlobalContext struct {
	Certificates         map[string]*x509.Certificate
	CertificateOccurrence map[string][]string
	certificateLock      sync.Mutex
	redirectHosts        []string
	redirectLock         sync.Mutex
	headerHosts          []string
	headerLock           sync.Mutex
	SearchHeaders        bool
	Whois                whois.WHOISCache
	DNSresolver          dns.DNSResolver
	DebugLog             *debug.DebugLogger
	Timeout              time.Duration
	UserAgent            string
}

func NewGlobalContext(dnsResolver dns.DNSResolver) *GlobalContext {
	return &GlobalContext{DNSresolver: dnsResolver, Whois: *whois.NewWHOISCache(), certificateLock: sync.Mutex{}, Certificates: make(map[string]*x509.Certificate), CertificateOccurrence: make(map[string][]string)}
}

func (g *GlobalContext) AddRedirect(redirect string) {
	g.redirectLock.Lock()
	defer g.redirectLock.Unlock()
	g.redirectHosts = append(g.redirectHosts, redirect)
	g.DNSresolver.AddHostname(redirect)
}

func (g *GlobalContext) AddCertificate(target string, certificate *x509.Certificate) {
	g.certificateLock.Lock()
	defer g.certificateLock.Unlock()
	if certificate == nil {
		return
	}
	if _, ok := g.Certificates[certificate.SerialNumber.String()]; !ok {
		g.Certificates[certificate.SerialNumber.String()] = certificate
		g.CertificateOccurrence[certificate.SerialNumber.String()] = []string{}
	}
	if !helpers.Contains(g.CertificateOccurrence[certificate.SerialNumber.String()], target) {
		g.CertificateOccurrence[certificate.SerialNumber.String()] = append(g.CertificateOccurrence[certificate.SerialNumber.String()], target)
	}
}

func (g *GlobalContext) RegisterCertificate(certificate *x509.Certificate) {
	g.certificateLock.Lock()
	defer g.certificateLock.Unlock()
	if certificate == nil {
		return
	}
	if _, ok := g.Certificates[certificate.SerialNumber.String()]; !ok {
		g.Certificates[certificate.SerialNumber.String()] = certificate
		g.CertificateOccurrence[certificate.SerialNumber.String()] = []string{}
	}
}

func (g *GlobalContext) CertificateHostnames() []string {
	g.certificateLock.Lock()
	defer g.certificateLock.Unlock()

	hostnames := []string{}
	for _, cert := range g.Certificates {
		hostnames = append(hostnames, cert.DNSNames...)
		hostnames = append(hostnames, cert.Subject.CommonName)
		for _, hostname := range cert.DNSNames {
			g.DNSresolver.AddHostname(hostname)
		}
	}

	return helpers.RemoveDuplicate(hostnames)
}

func (g *GlobalContext) AddHeaderHost(host string) {
	g.headerLock.Lock()
	defer g.headerLock.Unlock()
	g.headerHosts = append(g.headerHosts, host)
	g.DNSresolver.AddHostname(host)
}

func (g *GlobalContext) HeaderHostnames() []string {
	g.headerLock.Lock()
	defer g.headerLock.Unlock()
	g.headerHosts = helpers.RemoveDuplicate(g.headerHosts)
	return g.headerHosts
}

func (g *GlobalContext) RedirectHostnames() []string {
	g.redirectLock.Lock()
	defer g.redirectLock.Unlock()
	g.redirectHosts = helpers.RemoveDuplicate(g.redirectHosts)
	return g.redirectHosts
}

// GetCertificatesSnapshot returns a thread-safe snapshot of the certificates map
func (g *GlobalContext) GetCertificatesSnapshot() map[string]*x509.Certificate {
	g.certificateLock.Lock()
	defer g.certificateLock.Unlock()

	snapshot := make(map[string]*x509.Certificate, len(g.Certificates))
	for k, v := range g.Certificates {
		snapshot[k] = v
	}
	return snapshot
}

// GetCertificateOccurrenceSnapshot returns a thread-safe snapshot of the certificate occurrence map
func (g *GlobalContext) GetCertificateOccurrenceSnapshot() map[string][]string {
	g.certificateLock.Lock()
	defer g.certificateLock.Unlock()

	snapshot := make(map[string][]string, len(g.CertificateOccurrence))
	for k, v := range g.CertificateOccurrence {
		// Copy the slice to prevent shared references
		occurrences := make([]string, len(v))
		copy(occurrences, v)
		snapshot[k] = occurrences
	}
	return snapshot
}
