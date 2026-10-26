package globalcontext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/helpers"
)

func testCert(serial int64, cn string, sans ...string) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: sans}
}

func TestCertificateHostnames_SkipsReflectedCertificates(t *testing.T) {
	g := NewGlobalContext(dns.NewDNSResolver(""))
	defer g.DNSresolver.Stop()

	g.AddCertificate("1.2.3.4:443", testCert(1, "real.example.com", "real.example.com"))
	g.AddCertificate("1.2.3.4:443", testCert(2, "jkuq.wNjIpLPqGu.com"))
	g.MarkReflectedCertificate("2")

	got := g.CertificateHostnames()
	if !helpers.Contains(got, "real.example.com") {
		t.Fatalf("expected real hostname to be kept, got %v", got)
	}
	if helpers.Contains(got, "jkuq.wNjIpLPqGu.com") {
		t.Fatalf("reflected hostname must be skipped, got %v", got)
	}
}

func TestCertificateHostnames_SkipsIPLiterals(t *testing.T) {
	g := NewGlobalContext(dns.NewDNSResolver(""))
	defer g.DNSresolver.Stop()

	// IP literals in DNS-type SANs and as CommonName must not be queued.
	g.AddCertificate("1.2.3.4:443", testCert(7, "192.168.1.108", "real.example.com", "127.0.0.1", "[::1]"))

	got := g.CertificateHostnames()
	if !helpers.Contains(got, "real.example.com") {
		t.Fatalf("expected real hostname to be kept, got %v", got)
	}
	for _, ip := range []string{"192.168.1.108", "127.0.0.1", "[::1]"} {
		if helpers.Contains(got, ip) {
			t.Fatalf("IP literal %q must not be queued as a hostname, got %v", ip, got)
		}
	}
}

func TestAddRedirectAndHeaderHost_RejectInvalidNames(t *testing.T) {
	g := NewGlobalContext(dns.NewDNSResolver(""))
	defer g.DNSresolver.Stop()

	g.AddRedirect("  *. invalid .name ")
	g.AddHeaderHost("not a hostname")
	if len(g.RedirectHostnames()) != 0 {
		t.Fatalf("invalid redirect must be rejected, got %v", g.RedirectHostnames())
	}
	if len(g.HeaderHostnames()) != 0 {
		t.Fatalf("invalid header host must be rejected, got %v", g.HeaderHostnames())
	}

	g.AddRedirect(" real.example.com ")
	if got := g.RedirectHostnames(); len(got) != 1 || got[0] != "real.example.com" {
		t.Fatalf("valid redirect must be kept and trimmed, got %v", got)
	}
}

func TestTargetReflectsHost(t *testing.T) {
	g := NewGlobalContext(dns.NewDNSResolver(""))
	defer g.DNSresolver.Stop()

	if g.TargetReflectsHost("1.2.3.4:443") {
		t.Fatal("target must not be flagged by default")
	}
	g.MarkHTTPReflectingTarget("1.2.3.4:443")
	if !g.TargetReflectsHost("1.2.3.4:443") {
		t.Fatal("marked target must report as reflecting")
	}
}

func TestTargetIssuesRandomCerts(t *testing.T) {
	g := NewGlobalContext(dns.NewDNSResolver(""))
	defer g.DNSresolver.Stop()

	if g.TargetIssuesRandomCerts("1.2.3.4:443") {
		t.Fatal("target must not be flagged by default")
	}
	g.MarkDynamicTarget("1.2.3.4:443")
	if !g.TargetIssuesRandomCerts("1.2.3.4:443") {
		t.Fatal("marked target must report as dynamic")
	}
	if g.TargetIssuesRandomCerts("5.6.7.8:443") {
		t.Fatal("unmarked target must not be flagged")
	}
}

func TestIsReflectedCertificate_DefaultFalse(t *testing.T) {
	g := NewGlobalContext(dns.NewDNSResolver(""))
	defer g.DNSresolver.Stop()

	if g.IsReflectedCertificate("1") {
		t.Fatal("certificate must not be reflected by default")
	}
	g.MarkReflectedCertificate("1")
	if !g.IsReflectedCertificate("1") {
		t.Fatal("marked certificate must report as reflected")
	}
}

func TestCertificateHostnames_IncludesEmailDomains(t *testing.T) {
	g := NewGlobalContext(dns.NewDNSResolver(""))
	defer g.DNSresolver.Stop()

	// A device-vendor certificate whose only usable hostname is the domain of
	// its email address; the CN is an IP literal and must be dropped.
	cert := &x509.Certificate{
		SerialNumber:   big.NewInt(9),
		Subject:        pkix.Name{CommonName: "192.168.1.1"},
		EmailAddresses: []string{"support@lancom-systems.de"},
	}
	g.AddCertificate("1.2.3.4:443", cert)

	got := g.CertificateHostnames()
	if !helpers.Contains(got, "lancom-systems.de") {
		t.Fatalf("expected email domain to be queued for recon, got %v", got)
	}
	if helpers.Contains(got, "192.168.1.1") {
		t.Fatalf("IP literal must not be queued, got %v", got)
	}
}
