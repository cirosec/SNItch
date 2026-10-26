package tree

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/scanner"
)

// A certificate that only carries the hostname in its CommonName (no SAN) must
// still validate the hostname: SNItch tolerates the legacy CN fallback because
// it looks for information, not strict RFC 6125 correctness.
func TestFQDN_Print_CNOnlyCertificate(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "host.example.invalid"},
	}
	gctx.AddCertificate("10.0.0.1:443", cert)

	r := NewRootDomain()
	r.AddResult("host.example.invalid", &scanner.ScannerHostnameResult{Certificate: "42"})

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	rows := table.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.Hostname != "host.example.invalid" {
		t.Fatalf("expected FQDN row, got %+v", row)
	}
	if row.ValidCert == nil || !*row.ValidCert {
		t.Fatalf("expected cert_valid true from CommonName, got %v", row.ValidCert)
	}
}

// On a target that mints a per-SNI certificate, an echoed CommonName must not
// produce a hostname row even though CN matching is tolerated.
func TestFQDN_Print_DynamicTargetSuppressesRow(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "host.example.invalid"},
	}
	gctx.AddCertificate("10.0.0.1:443", cert)
	gctx.MarkDynamicTarget("10.0.0.1:443")

	r := NewRootDomain()
	r.AddResult("host.example.invalid", &scanner.ScannerHostnameResult{Certificate: "42"})

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	if len(table.Rows()) != 0 {
		t.Fatalf("expected no rows for a dynamic target, got %d", len(table.Rows()))
	}
}
