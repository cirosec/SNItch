package helpers

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
)

func TestCertHostnames_SANAndCN(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "cn.example.com"},
		DNSNames: []string{"san.example.com", "cn.example.com"},
	}
	got := CertHostnames(cert)
	if !Contains(got, "san.example.com") {
		t.Fatalf("expected SAN name, got %v", got)
	}
	if !Contains(got, "cn.example.com") {
		t.Fatalf("expected CN name, got %v", got)
	}
	if len(got) != 2 {
		t.Fatalf("expected deduplicated list of 2, got %v", got)
	}
}

func TestCertHostnames_CNOnly(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "legacy.example.org"}}
	got := CertHostnames(cert)
	if len(got) != 1 || got[0] != "legacy.example.org" {
		t.Fatalf("expected CN-only name, got %v", got)
	}
}

func TestCertHostnames_Nil(t *testing.T) {
	if CertHostnames(nil) != nil {
		t.Fatal("nil certificate must yield nil")
	}
}

func TestCertEmailDomains_FromDNEmailAttribute(t *testing.T) {
	// Mirrors a LANCOM router: the vendor domain lives only in the legacy
	// emailAddress DN attribute, which Go exposes via Subject/Issuer.Names.
	email := pkix.AttributeTypeAndValue{Type: oidEmailAddress, Value: "info@lancom-systems.de"}
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "93.236.194.37", Names: []pkix.AttributeTypeAndValue{email}},
		Issuer:  pkix.Name{CommonName: "93.236.194.37", Names: []pkix.AttributeTypeAndValue{email}},
	}
	got := CertEmailDomains(cert)
	if len(got) != 1 || got[0] != "lancom-systems.de" {
		t.Fatalf("expected deduplicated lancom-systems.de, got %v", got)
	}
	if emails := CertEmailAddresses(cert); len(emails) != 1 || emails[0] != "info@lancom-systems.de" {
		t.Fatalf("expected full email address, got %v", emails)
	}
}

func TestCertEmailDomains_FromSANSAN(t *testing.T) {
	cert := &x509.Certificate{EmailAddresses: []string{"admin@Vendor.EXAMPLE.com"}}
	got := CertEmailDomains(cert)
	if len(got) != 1 || got[0] != "vendor.example.com" {
		t.Fatalf("expected lowercased vendor.example.com, got %v", got)
	}
}

func TestCertEmailDomains_RejectsNonDomains(t *testing.T) {
	cert := &x509.Certificate{EmailAddresses: []string{"no-at-sign", "trailing@", "user@not a hostname"}}
	if got := CertEmailDomains(cert); len(got) != 0 {
		t.Fatalf("expected no usable domains, got %v", got)
	}
}

func TestCertURIHosts(t *testing.T) {
	cert := &x509.Certificate{URIs: []*url.URL{
		{Scheme: "https", Host: "provision.example.net"},
		{Host: "127.0.0.1"},
	}}
	got := CertURIHosts(cert)
	if len(got) != 1 || got[0] != "provision.example.net" {
		t.Fatalf("expected provision.example.net and no IP literal, got %v", got)
	}
}

func TestCertOrganizations_DisplayOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{Organization: []string{"LANCOM Systems"}, OrganizationalUnit: []string{"Engineering"}},
		Issuer:  pkix.Name{Organization: []string{"LANCOM Systems"}},
	}
	if got := CertOrganizations(cert); len(got) != 1 || got[0] != "LANCOM Systems" {
		t.Fatalf("expected deduplicated organization, got %v", got)
	}
	// Organization/OU free text must never be treated as a hostname source.
	if got := CertEmailDomains(cert); len(got) != 0 {
		t.Fatalf("organization/OU must not yield hostnames, got %v", got)
	}
	if got := CertURIHosts(cert); len(got) != 0 {
		t.Fatalf("organization/OU must not yield URI hosts, got %v", got)
	}
}
