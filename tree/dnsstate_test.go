package tree

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"

	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/scanner"
)

type fakeResolver struct {
	ips []net.IP
	err error
}

func (f *fakeResolver) Resolve(string) ([]net.IP, error) { return f.ips, f.err }
func (f *fakeResolver) AddHostname(string) error        { return nil }
func (f *fakeResolver) Stop()                            {}

func TestDNSStateFor(t *testing.T) {
	targetIP := net.ParseIP("10.0.0.1")
	tests := []struct {
		name     string
		hostname string
		target   string
		ips      []net.IP
		err      error
		want     DNSState
	}{
		{"wildcard not applicable", "*.example.com", "10.0.0.1:443", []net.IP{targetIP}, nil, DNSNotApplicable},
		{"empty hostname not applicable", "", "10.0.0.1:443", nil, nil, DNSNotApplicable},
		{"resolve error", "gone.example.com", "10.0.0.1:443", nil, errors.New("nxdomain"), DNSUnresolved},
		{"empty result unresolved", "gone.example.com", "10.0.0.1:443", []net.IP{}, nil, DNSUnresolved},
		{"resolves to target", "www.example.com", "10.0.0.1:443", []net.IP{targetIP}, nil, DNSResolvesToTarget},
		{"resolves elsewhere", "www.example.com", "10.0.0.1:443", []net.IP{net.ParseIP("198.51.100.7")}, nil, DNSResolvesElsewhere},
		{"unparseable target", "www.example.com", "not-a-target", nil, nil, DNSUnresolved},
		{"non-IP target host", "www.example.com", "example.com:443", []net.IP{targetIP}, nil, DNSNotApplicable},
	}
	for _, tt := range tests {
		gctx := &globalcontext.GlobalContext{DNSresolver: &fakeResolver{ips: tt.ips, err: tt.err}}
		if got := dnsStateFor(gctx, tt.target, tt.hostname); got != tt.want {
			t.Errorf("%s: dnsStateFor() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// A certificate SAN that differs only in case from the discovered FQDN must
// still validate the finding.
func TestFQDN_Print_CaseInsensitiveCertValidation(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(&fakeResolver{})
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		DNSNames:    []string{"www.Example.COM"},
		Subject:      pkix.Name{CommonName: "www.Example.COM"},
	}
	gctx.AddCertificate("10.0.0.1:443", cert)

	r := NewRootDomain()
	r.AddResult("www.example.com", &scanner.ScannerHostnameResult{Certificate: "7"})

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	rows := table.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].Hostname != "www.example.com" {
		t.Fatalf("expected FQDN row, got %+v", rows[0])
	}
	if rows[0].ValidCert == nil || !*rows[0].ValidCert {
		t.Fatalf("expected cert_valid true for case-differing SAN, got %v", rows[0].ValidCert)
	}
}