package helpers

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// CertHostnames returns the names a certificate may be matched against under a
// tolerant, legacy-compatible interpretation: its SAN DNS entries plus its
// CommonName. Modern clients ignore CN whenever SANs are present, but SNItch is
// looking for information rather than strict certificate correctness, so a
// CN-only certificate still surfaces the hostname it identifies.
// SanitizeHostname returns the canonical form of a candidate name (see
// CanonicalHostname) and reports whether it is a usable hostname. Names that
// fail validation must not be fed into the scan queue or used to build tree
// nodes.
func SanitizeHostname(name string) (string, bool) {
	return CanonicalHostname(name)
}

// CanonicalHostname returns the canonical form of a hostname: trimmed,
// without trailing dots, lowercased, with IDN U-labels converted to punycode
// A-labels. A leading "*." wildcard prefix is preserved and canonicalized with
// the name. ok is false when the result is not a syntactically valid hostname;
// in that case no name is returned.
func CanonicalHostname(name string) (string, bool) {
	name = strings.TrimSpace(name)
	prefix := ""
	if strings.HasPrefix(name, "*.") {
		prefix = name[:2]
		name = name[2:]
	}
	name = strings.ToLower(strings.TrimRight(name, "."))
	if ascii, err := idna.ToASCII(name); err == nil {
		// idna tolerates underscores; on error fall back to the lowered
		// name and let IsValidHostname decide.
		name = strings.ToLower(ascii)
	}
	if !IsValidHostname(prefix + name) {
		return "", false
	}
	return prefix + name, true
}

// IsValidHostname reports whether name is syntactically a valid DNS hostname
// (RFC 1123, plus underscore-bearing labels such as "_dmarc.example.com" that
// occur in real SANs and DNS), optionally prefixed with "*." for a wildcard.
// It deliberately does not require a public suffix, so single-label names
// ("synology", "localhost") and internal names ("host.corp.local") are
// accepted as long as they are well-formed; SNItch is tolerant and after
// information.
func IsValidHostname(name string) bool {
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' && c != '_' {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func CertHostnames(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	names := make([]string, 0, len(cert.DNSNames)+1)
	names = append(names, cert.DNSNames...)
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		names = append(names, cn)
	}
	return RemoveDuplicate(names)
}

// oidEmailAddress is the object identifier of the legacy PKCS#9 emailAddress
// attribute that may appear in a certificate's subject or issuer DN. Go exposes
// it neither as pkix.Name.EmailAddresses nor via x509.Certificate.EmailAddresses
// (which only holds SAN rfc822Name entries), so it must be read from the raw
// Name attribute list.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// EmailDomain returns the domain part of an email address, or ok=false when it
// carries no usable domain. Only the domain is returned: the local part is a
// mailbox, not a hostname.
func EmailDomain(email string) (string, bool) {
	email = strings.TrimSpace(email)
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return "", false
	}
	domain, ok := SanitizeHostname(strings.ToLower(email[at+1:]))
	if !ok || IsIPLiteral(domain) {
		return "", false
	}
	return domain, true
}

// CertEmailAddresses returns every email address a certificate carries: SAN
// rfc822Name entries plus the legacy emailAddress attribute in the subject and
// issuer DNs. These often name the device vendor and are otherwise invisible to
// SNItch's DNS-SAN-only parsing.
func CertEmailAddresses(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	emails := make([]string, 0, len(cert.EmailAddresses)+2)
	emails = append(emails, cert.EmailAddresses...)
	emails = append(emails, emailAttributes(cert.Subject)...)
	emails = append(emails, emailAttributes(cert.Issuer)...)
	cleaned := make([]string, 0, len(emails))
	for _, e := range emails {
		if e = strings.TrimSpace(e); e != "" {
			cleaned = append(cleaned, e)
		}
	}
	return RemoveDuplicate(cleaned)
}

// CertEmailDomains returns the deduplicated domains of all email addresses in a
// certificate (see CertEmailAddresses). Only domains that are syntactically
// valid hostnames are returned.
func CertEmailDomains(cert *x509.Certificate) []string {
	domains := []string{}
	for _, email := range CertEmailAddresses(cert) {
		if domain, ok := EmailDomain(email); ok {
			domains = append(domains, domain)
		}
	}
	return RemoveDuplicate(domains)
}

// CertOrganizations returns the organization (O) values of the subject and
// issuer DNs, deduplicated. Intended for display only: organization names are
// free text and must not be treated as hostnames.
func CertOrganizations(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	orgs := make([]string, 0, len(cert.Subject.Organization)+len(cert.Issuer.Organization))
	orgs = append(orgs, cert.Subject.Organization...)
	orgs = append(orgs, cert.Issuer.Organization...)
	cleaned := make([]string, 0, len(orgs))
	for _, o := range orgs {
		if o = strings.TrimSpace(o); o != "" {
			cleaned = append(cleaned, o)
		}
	}
	return RemoveDuplicate(cleaned)
}

// CertURIHosts returns the hostnames of every URI SAN entry, deduplicated. Such
// URIs (e.g. a provisioning or management endpoint) can reveal a hostname that
// the DNS SANs omit.
func CertURIHosts(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	hosts := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		if host, ok := SanitizeHostname(u.Hostname()); ok && !IsIPLiteral(host) {
			hosts = append(hosts, host)
		}
	}
	return RemoveDuplicate(hosts)
}

// emailAttributes extracts the values of the legacy emailAddress attribute from
// a parsed distinguished name.
func emailAttributes(name pkix.Name) []string {
	out := []string{}
	for _, attr := range name.Names {
		if attr.Type.Equal(oidEmailAddress) {
			if value, ok := attr.Value.(string); ok {
				out = append(out, value)
			}
		}
	}
	return out
}

func FQDNToSLD(FQDN string) (string, error) {
	// Converts lol.example.com to example.com
	// Handles multi-part TLDs like co.uk, com.au correctly:
	//   foo.co.uk -> foo.co.uk
	//   bar.example.co.uk -> example.co.uk
	FQDN = strings.TrimPrefix(FQDN, "*.")
	sld, err := publicsuffix.EffectiveTLDPlusOne(FQDN)
	if err != nil {
		return "", fmt.Errorf("unable to convert FQDN to SLD: %w", err)
	}
	return sld, nil
}

func GetLabelByLevelFromFQDN(fqdn string, level int) (string, string) {
	cleanFqdn := strings.TrimPrefix(fqdn, "*.")
	sld, err := publicsuffix.EffectiveTLDPlusOne(cleanFqdn)
	if err != nil {
		// Fallback: treat entire string as the SLD
		return "", fqdn
	}
	sldParts := strings.Split(sld, ".")
	tmp := strings.Split(fqdn, ".")
	if len(tmp) <= len(sldParts) {
		return "", fqdn
	}
	if level == 0 { // Return SLD
		return "", sld
	}
	sldDepth := len(sldParts)
	idx := len(tmp) - (level + sldDepth)
	last := ""
	if idx >= 0 {
		last = tmp[idx]
	}
	start := idx + 1
	if start < 0 {
		start = 0
	}
	return last, strings.Join(tmp[start:], ".")
}
