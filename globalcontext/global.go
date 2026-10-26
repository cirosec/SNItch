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
	Certificates          map[string]*x509.Certificate
	CertificateOccurrence map[string][]string
	certificateLock       sync.Mutex
	reflectedCerts        map[string]bool // serials of certificates that echo the requested SNI (dynamic issuer)
	dynamicTargets        map[string]bool // targets whose server issues a per-SNI certificate
	httpReflectTargets    map[string]bool // targets whose server reflects the requested Host into redirects
	reflectedLock         sync.Mutex
	redirectHosts         []string
	redirectLock          sync.Mutex
	headerHosts           []string
	headerLock            sync.Mutex
	SearchHeaders         bool
	Whois                 whois.WHOISCache
	DNSresolver           dns.DNSResolver
	DebugLog              *debug.DebugLogger
	Timeout               time.Duration
	UserAgent             string
}

func NewGlobalContext(dnsResolver dns.DNSResolver) *GlobalContext {
	return &GlobalContext{DNSresolver: dnsResolver, Whois: *whois.NewWHOISCache(), certificateLock: sync.Mutex{}, Certificates: make(map[string]*x509.Certificate), CertificateOccurrence: make(map[string][]string), reflectedCerts: make(map[string]bool), dynamicTargets: make(map[string]bool), httpReflectTargets: make(map[string]bool)}
}

func (g *GlobalContext) AddRedirect(redirect string) {
	redirect, ok := helpers.SanitizeHostname(redirect)
	if !ok {
		return
	}
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

// MarkReflectedCertificate records that the certificate with the given serial
// was issued in response to an unknown/random SNI and merely echoes that name.
// Names from such certificates must not be fed back into recon.
func (g *GlobalContext) MarkReflectedCertificate(serial string) {
	g.reflectedLock.Lock()
	defer g.reflectedLock.Unlock()
	if g.reflectedCerts == nil {
		g.reflectedCerts = make(map[string]bool)
	}
	g.reflectedCerts[serial] = true
}

// IsReflectedCertificate reports whether the certificate with the given serial
// was flagged as a reflected (per-SNI dynamically issued) certificate.
func (g *GlobalContext) IsReflectedCertificate(serial string) bool {
	g.reflectedLock.Lock()
	defer g.reflectedLock.Unlock()
	return g.reflectedCerts[serial]
}

// MarkDynamicTarget records that the server behind target issues a distinct
// certificate per SNI. Hostnames validated against such a target are
// reflections and must not be reported as findings.
func (g *GlobalContext) MarkDynamicTarget(target string) {
	g.reflectedLock.Lock()
	defer g.reflectedLock.Unlock()
	if g.dynamicTargets == nil {
		g.dynamicTargets = make(map[string]bool)
	}
	g.dynamicTargets[target] = true
}

// TargetIssuesRandomCerts reports whether target was flagged as issuing a
// per-SNI (dynamic) certificate.
func (g *GlobalContext) TargetIssuesRandomCerts(target string) bool {
	g.reflectedLock.Lock()
	defer g.reflectedLock.Unlock()
	return g.dynamicTargets[target]
}

// MarkHTTPReflectingTarget records that the server behind target reflects the
// requested Host back in its redirect (a catch-all), so redirect-based host
// discovery against it is not a real finding.
func (g *GlobalContext) MarkHTTPReflectingTarget(target string) {
	g.reflectedLock.Lock()
	defer g.reflectedLock.Unlock()
	if g.httpReflectTargets == nil {
		g.httpReflectTargets = make(map[string]bool)
	}
	g.httpReflectTargets[target] = true
}

// TargetReflectsHost reports whether target was flagged as reflecting the
// requested Host into its HTTP redirects.
func (g *GlobalContext) TargetReflectsHost(target string) bool {
	g.reflectedLock.Lock()
	defer g.reflectedLock.Unlock()
	return g.httpReflectTargets[target]
}

func (g *GlobalContext) CertificateHostnames() []string {
	g.certificateLock.Lock()
	defer g.certificateLock.Unlock()

	hostnames := []string{}
	for serial, cert := range g.Certificates {
		// Skip certificates whose names are just the requested SNI echoed back
		// by a dynamic issuer; they reveal no real hostnames and would only
		// pollute the scan queue.
		if g.IsReflectedCertificate(serial) {
			continue
		}
		// DNS-type SAN entries may hold IP literals (e.g. "127.0.0.1" or
		// "[::1]"); those are addresses, not hostnames, and must not be queued.
		// Names are sanitized so malformed entries never pollute the queue.
		for _, hostname := range cert.DNSNames {
			name, ok := helpers.SanitizeHostname(hostname)
			if !ok || helpers.IsIPLiteral(name) {
				continue
			}
			hostnames = append(hostnames, name)
			g.DNSresolver.AddHostname(name)
		}
		if cn, ok := helpers.SanitizeHostname(cert.Subject.CommonName); ok && !helpers.IsIPLiteral(cn) {
			hostnames = append(hostnames, cn)
		}
		// Email domains and URI SAN hosts frequently name the device vendor or a
		// management endpoint (e.g. a LANCOM router's info@lancom-systems.de) and
		// are invisible to DNS-SAN-only parsing.
		extra := append(helpers.CertEmailDomains(cert), helpers.CertURIHosts(cert)...)
		for _, name := range extra {
			if helpers.IsIPLiteral(name) {
				continue
			}
			hostnames = append(hostnames, name)
			g.DNSresolver.AddHostname(name)
		}
	}

	return helpers.RemoveDuplicate(hostnames)
}

func (g *GlobalContext) AddHeaderHost(host string) {
	host, ok := helpers.SanitizeHostname(host)
	if !ok {
		return
	}
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
