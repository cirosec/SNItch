package scanner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
)

func testCert(cn string, sans []string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, DNSNames: sans}
}

func TestReflectsSNI_CommonNameEcho(t *testing.T) {
	if !reflectsSNI(testCert("jkuq.wNjIpLPqGu.com", nil), "jkuq.wNjIpLPqGu.com") {
		t.Fatal("expected CN echo to be detected")
	}
}

func TestReflectsSNI_CommonNameCaseInsensitive(t *testing.T) {
	if !reflectsSNI(testCert("JKUQ.WNJIPLPQGU.COM", nil), "jkuq.wNjIpLPqGu.com") {
		t.Fatal("expected case-insensitive CN echo to be detected")
	}
}

func TestReflectsSNI_SANEcho(t *testing.T) {
	if !reflectsSNI(testCert("other", []string{"jkuq.wNjIpLPqGu.com"}), "jkuq.wNjIpLPqGu.com") {
		t.Fatal("expected SAN echo to be detected")
	}
}

func TestReflectsSNI_UnrelatedCert(t *testing.T) {
	if reflectsSNI(testCert("example.com", []string{"example.com", "*.example.com"}), "jkuq.wNjIpLPqGu.com") {
		t.Fatal("unrelated certificate must not be flagged as reflecting")
	}
}

func TestReflectsSNI_NilAndEmpty(t *testing.T) {
	if reflectsSNI(nil, "example.com") {
		t.Fatal("nil certificate must not be flagged")
	}
	if reflectsSNI(testCert("", nil), "") {
		t.Fatal("empty requested SNI must not be flagged")
	}
}

func serialCert(serial int64, cn string) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}}
}

func TestMarkMintedCertificate_DynamicTargetEcho(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()
	target := "1.2.3.4:443"
	gctx.MarkDynamicTarget(target)
	s := NewSNIHostnameResult("w28.dyndns.org", target, gctx)

	// A dynamic issuer mints a certificate echoing the requested encoding
	// variant; the minted names must not be probed against other targets.
	minted := serialCert(42, "W28.DYNDNS.ORG")
	s.markMintedCertificate(target, minted, "W28.DYNDNS.ORG")
	if !gctx.IsReflectedCertificate("42") {
		t.Fatal("certificate minted by a dynamic issuer must be marked reflected")
	}

	// A certificate that does not contain the requested name is the target's
	// real (static) certificate; its names stay usable.
	static := serialCert(43, "other.example.com")
	s.markMintedCertificate(target, static, "w28.dyndns.org")
	if gctx.IsReflectedCertificate("43") {
		t.Fatal("static certificate on a dynamic target must not be marked")
	}
}

func TestMarkMintedCertificate_StaticTargetNeverMarked(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()
	target := "5.6.7.8:443"
	s := NewSNIHostnameResult("w28.dyndns.org", target, gctx)

	// A normal server legitimately serves a certificate containing the
	// requested hostname; that is the expected SNI behavior, not a reflection.
	cert := serialCert(44, "w28.dyndns.org")
	s.markMintedCertificate(target, cert, "w28.dyndns.org")
	if gctx.IsReflectedCertificate("44") {
		t.Fatal("certificate from a static target must not be marked reflected")
	}
}
