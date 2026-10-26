package tree

import (
	"testing"

	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/scanner"
)

// A server that mints a unique certificate per SNI must surface a
// (RANDOM CERT) pseudo-row so the reader knows its hostnames are reflections.
func TestRootDomain_Print_RandomCertRow(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	r := NewRootDomain()
	r.result = &scanner.ScannerRootResult{
		Target:          "93.235.253.87:443",
		SNIReflectsName: scanner.TriStateTrue,
	}

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "93.235.253.87:443"})
	rows := table.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.AlternateText == nil || *row.AlternateText != "(RANDOM CERT)" {
		t.Fatalf("expected (RANDOM CERT) row, got %+v", row)
	}
	if row.ValidCert != nil {
		t.Fatalf("random-cert row must not assert certificate validity, got %v", *row.ValidCert)
	}
}

func TestRootDomain_Print_NoRandomCertRowWhenUnset(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	r := NewRootDomain()
	r.result = &scanner.ScannerRootResult{Target: "10.0.0.1:443"}

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	if len(table.Rows()) != 0 {
		t.Fatalf("expected no rows, got %d", len(table.Rows()))
	}
}
