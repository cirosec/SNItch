package tree

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/models"
	"github.com/cirosec/snitch/scanner"

	"github.com/fatih/color"
)

func ForestBuilder(targets []string, results map[models.ScanContextResultKey]interface{}) map[string]*RootDomain {
	forest := map[string]*RootDomain{}
	for _, target := range targets {
		forest[target] = NewRootDomain()
	}
	for key, value := range results {
		forest[key.Target].AddResult(key.Host, value)
	}
	return forest
}

type PrintConfig struct {
	Root       *RootDomain
	Target     string
	AllTargets []string
}

// BuildTable assembles the MiniTable for a target. It is shared by the
// human-readable printer and the JSONL exporter, so both emit identical rows.
func (r *RootDomain) BuildTable(gctx *globalcontext.GlobalContext, c *PrintConfig) *MiniTable {
	//Sorting as go can't handle it itself
	keys := make([]string, 0, len(r.Labels))

	for k := range r.Labels {
		keys = append(keys, k)
	}
	helpers.SortDomains(keys)

	table := NewTable()

	//Actually build the result
	r.Print(gctx, c, table)
	for _, value := range keys {
		r.Labels[value].Print(gctx, c, table, r)
	}
	return table
}

// PrintTargetHeading prints the block-cased target heading with a reverse DNS
// annotation when available. The PTR lookup is bounded so a slow resolver can
// not stall the report after the scan has ended.
func PrintTargetHeading(target string) {
	ipColor := color.New(color.FgBlack, color.BgWhite).SprintFunc()
	fmt.Println()
	heading := fmt.Sprintf("%50v", target)
	if ip, _, err := net.SplitHostPort(target); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
			heading += "  (" + strings.TrimSuffix(names[0], ".") + ")"
		}
	}
	fmt.Print(ipColor(heading) + "\n")
}

// dnsStateFor computes how hostname's DNS records relate to the target IP.
// It returns DNSNotApplicable for wildcards, the empty pseudo-host and the
// IP-as-SNI pseudo-host, matching the table's historical behavior.
func dnsStateFor(gctx *globalcontext.GlobalContext, target, hostname string) DNSState {
	if strings.HasPrefix(hostname, "*") || hostname == "" {
		return DNSNotApplicable
	}
	dnsrecords, err := gctx.DNSresolver.Resolve(hostname)
	pureTarget, _, errTarget := net.SplitHostPort(target)
	// An empty result with no error (e.g. a lookup that returned no records)
	// is also unresolved; otherwise such hosts would be reported as
	// "resolves elsewhere".
	if err != nil || errTarget != nil || len(dnsrecords) == 0 {
		return DNSUnresolved
	}
	targetIP := net.ParseIP(pureTarget)
	if targetIP == nil {
		return DNSNotApplicable
	}
	for _, element := range dnsrecords {
		if targetIP.Equal(element) {
			return DNSResolvesToTarget
		}
	}
	return DNSResolvesElsewhere
}

func (r *RootDomain) Print(gctx *globalcontext.GlobalContext, c *PrintConfig, table *MiniTable) {
	// gctx attributes are not locked here. This is not a problem, since the scan has already ended. Hence this function is the only one using the data.
	if r.result == nil {
		return
	}
	// Show the plaintext HTTP (IP-only) result when the server responded to it.
	// The host variant that produced the result is shown as the row label so
	// the reader can tell whether the IP, a random hostname, an invalid
	// hostname or the Host-less HTTP/1.0 probe triggered the reveal. The
	// random and no-host probes are summarized because their values carry no
	// meaning or are absent.
	if r.result.PlainHTTPStatus != 0 {
		alternate := "(HTTP)"
		if r.result.PlainHTTPHost != "" || r.result.PlainHTTPHostNoHost {
			alternate = plainHTTPHostLabel("(HTTP", r.result.PlainHTTPHost, r.result.PlainHTTPHostRandom, r.result.PlainHTTPHostNoHost)
		}
		row := NewRow("", nil, Pointer(r.result.PlainHTTPStatus), r.result.PlainHTTPTitle, Pointer(r.result.PlainHTTPRedirect), Pointer(alternate))
		row.DNS = DNSNotApplicable
		table.AddRow(row)
	}

	// Show the plaintext HTTP result against the target's own (TLS) port when
	// that probe revealed a hostname. A benign rejection (e.g. "400 The plain
	// HTTP request was sent to HTTPS port") reveals nothing and produces no row.
	if r.result.PlainHTTPTLSStatus != 0 {
		alternate := "(HTTP/TLS)"
		if r.result.PlainHTTPTLSHost != "" || r.result.PlainHTTPTLSHostNoHost {
			alternate = plainHTTPHostLabel("(HTTP/TLS", r.result.PlainHTTPTLSHost, r.result.PlainHTTPTLSHostRandom, r.result.PlainHTTPTLSHostNoHost)
		}
		row := NewRow("", nil, Pointer(r.result.PlainHTTPTLSStatus), r.result.PlainHTTPTLSTitle, Pointer(r.result.PlainHTTPTLSRedirect), Pointer(alternate))
		row.DNS = DNSNotApplicable
		row.PlainHTTPTLS = true
		table.AddRow(row)
	}

	if r.result.SNIAllowsMissing == scanner.TriStateTrue || r.result.SNIAllowsEmptyWithExt == scanner.TriStateTrue {
		// The row must describe a real no-SNI/empty-SNI connection, not the
		// random-SNI probe. Triggering on SNIDisconnectsOnRandom or
		// SNIAllowsEmpty (spaces) mislabeled hardened servers as leaking.
		row := NewRow("", nil, nil, "", nil, Pointer("(EMPTY SNI)"))
		if r.result.EmptySNIHttpStatus != 0 {
			row.HTTPStatus = Pointer(r.result.EmptySNIHttpStatus)
			row.HTTPTitle = r.result.EmptySNIHttpTitle
			row.HTTPRedirect = Pointer(r.result.EmptySNIHttpRedirect)
		}
		row.DNS = DNSNotApplicable
		table.AddRow(row)
	}

	// Show IP-as-SNI result when the server accepted it and the result is interesting:
	// either the certificate differs from the fallback or the certificate has the IP in its SANs
	if r.result.SNIAllowsIPasSNI == scanner.TriStateTrue && len(r.result.SNIIPCertificate) > 0 {
		differentFromFallback := r.result.SNIIPCertificate != r.result.SNIFallbackCertificate
		ipInSAN := false
		if cert, ok := gctx.Certificates[r.result.SNIIPCertificate]; ok {
			targetIP, _, err := net.SplitHostPort(c.Target)
			if err == nil {
				parsed := net.ParseIP(targetIP)
				for _, sanIP := range cert.IPAddresses {
					if parsed != nil && sanIP.Equal(parsed) {
						ipInSAN = true
						break
					}
				}
			}
		}
		if differentFromFallback || ipInSAN {
			row := NewRow(c.Target, Pointer(ipInSAN), nil, "", nil, Pointer("(IP as SNI)"))
			row.DNS = DNSNotApplicable
			table.AddRow(row)
		}
	}

	// A server that mints a unique certificate per SNI (echoing the requested
	// name) makes every "discovered" hostname a mere reflection. Flag the
	// target so the reader knows hostnames from it are not real vhosts.
	if r.result.SNIReflectsName == scanner.TriStateTrue {
		row := NewRow(c.Target, nil, nil, "", nil, Pointer("(RANDOM CERT)"))
		row.DNS = DNSNotApplicable
		table.AddRow(row)
	}
}

func (s *DomainLabel) Print(gctx *globalcontext.GlobalContext, c *PrintConfig, table *MiniTable, parent ParentNode) {
	//fmt.Printf("%s Result: %v\n", s.DomainPrefix, s.result)
	s.Hostname.Print(gctx, c, parent, table)
	s.PrintWildcard(gctx, c, table, parent)
	//Sorting as go can't handle it itself
	keys := make([]string, 0, len(s.Labels))

	for k := range s.Labels {
		keys = append(keys, k)
	}
	helpers.SortDomains(keys)
	//Actually print the result
	for _, value := range keys {
		s.Labels[value].Print(gctx, c, table, s)
	}
}

func (s *DomainLabel) PrintWildcard(gctx *globalcontext.GlobalContext, c *PrintConfig, table *MiniTable, parent ParentNode) {
	if s.result == nil {
		return
	}
	// A certificate minted for the random wildcard probe that merely echoes the
	// probe name must not be used to claim a wildcard vhost. The target-level
	// flag covers all wildcard probes against a per-SNI issuer.
	CertReflected := (len(s.result.SNIFallbackCertificate) > 0 && gctx.IsReflectedCertificate(s.result.SNIFallbackCertificate)) ||
		gctx.TargetIssuesRandomCerts(c.Target)

	// A catch-all that reflects the requested Host into its redirect must not be
	// treated as HTTP evidence for a wildcard vhost.
	HTTPReflectedHost := s.result.HTTPReflectsHost || gctx.TargetReflectsHost(c.Target)

	// Check if the certificate for the random subdomain of this wildcard is the same certificate as the root fallback certificate
	NotAFallbackCertificate := len(s.result.SNIFallbackCertificate) > 0 && c.Root.HasResult() && len(c.Root.SNIFallbackCertificate()) > 0 &&
		s.result.SNIFallbackCertificate != c.Root.SNIFallbackCertificate()

	// Check if the certificate for the random subdomain of this wildcard actually matches the hostname
	CertificateMatchesHostname := !CertReflected && s.result.SNIresult == nil && len(s.result.SNIFallbackCertificate) > 0 &&
		helpers.ContainsFold(helpers.CertHostnames(gctx.Certificates[s.result.SNIFallbackCertificate]), "*."+s.DomainPrefix)

	// Check status code for plausibility
	HTTPResult := s.result.HttpStatus != 0

	// Check for HTTP Fallback by comparing URL paths (not full URLs).
	// Catch-all servers echo the requested hostname in redirects, making full URL
	// comparison fail even though the redirect path is identical.
	redirectPath := helpers.GetURLPath(s.result.HttpRedirect)

	// Compare against parent (wildcard at parent level)
	HTTPFallbackParent := parent.HasResult() &&
		(helpers.GetURLPath(parent.HttpRedirect()) == redirectPath ||
			parent.HttpTitle() == s.result.HttpTitle) &&
		s.result.HttpStatus == parent.HttpStatus()

	// Also compare against root to catch top-level wildcards from catch-all servers
	HTTPFallbackRoot := c.Root.HasResult() &&
		(helpers.GetURLPath(c.Root.HttpRedirect()) == redirectPath ||
			c.Root.HttpTitle() == s.result.HttpTitle) &&
		s.result.HttpStatus == c.Root.HttpStatus()

	HTTPFallback := HTTPFallbackParent || HTTPFallbackRoot

	// Show the wildcard if:
	// - Certificate explicitly matches the wildcard domain (strong signal), OR
	// - HTTP behavior differs from both parent and root fallback AND either the cert
	//   is different or an HTTP result exists (a different cert alone is not enough
	//   if HTTP behaves identically to the catch-all)
	if !CertReflected && s.result.SNIresult == nil &&
		(CertificateMatchesHostname || (!HTTPReflectedHost && (NotAFallbackCertificate || HTTPResult) && !HTTPFallback)) {
		var row *MiniRow
		if HTTPResult {
			row = NewRow("*."+s.DomainPrefix, Pointer(CertificateMatchesHostname), Pointer(s.result.HttpStatus), s.result.HttpTitle, Pointer(s.result.HttpRedirect), nil)
		} else {
			row = NewRow("*."+s.DomainPrefix, Pointer(CertificateMatchesHostname), nil, "", Pointer(""), nil)
		}
		row.Wildcard = true
		row.DNS = DNSNotApplicable
		table.AddRow(row)
	}
}

func Pointer[T any](d T) *T {
	return &d
}

// plainHTTPHostLabel renders the row label for a plaintext-HTTP reveal. A
// generated random hostname is summarized as "random" because its ephemeral
// value would otherwise look like a discovered domain; the Host-less HTTP/1.0
// probe is labeled "no-host"; the IP and invalid "$" variants are shown
// verbatim.
func plainHTTPHostLabel(prefix, host string, random, noHost bool) string {
	if noHost {
		return prefix + " no-host)"
	}
	if random {
		return prefix + " random)"
	}
	return prefix + " " + host + ")"
}

func (h *FQDN) Print(gctx *globalcontext.GlobalContext, c *PrintConfig, parent ParentNode, table *MiniTable) {
	if h.result == nil {
		return
	}

	// Certificates issued dynamically for whatever SNI was requested merely
	// echo the name and must never validate a hostname. The target-level flag
	// also covers hostnames we probed ourselves, whose echoed certificate was
	// not flagged individually.
	CertReflected := (len(h.result.Certificate) > 0 && gctx.IsReflectedCertificate(h.result.Certificate)) ||
		gctx.TargetIssuesRandomCerts(c.Target)

	// Names the certificate may be matched against (SANs plus CN, tolerating
	// the legacy CN fallback because SNItch is after information, not strict
	// certificate correctness).
	CertNames := helpers.CertHostnames(gctx.Certificates[h.result.Certificate])

	// if the certificate used for this domain is valid for the domain
	IsValidCert := !CertReflected && helpers.DNSDomainInArray(CertNames, h.FQDN)

	// If the domain was explicitly issued a certificate which is not a wildcard certificate
	IsValidSpecificCert := !CertReflected && helpers.ContainsFold(CertNames, h.FQDN)

	// If the certificate used for this domain is also the certificate used when requesting a random subdomain on the same level
	IsFallBackCertificate := parent.HasResult() && len(h.result.Certificate) > 0 && len(parent.SNIFallbackCertificate()) > 0 &&
		parent.SNIFallbackCertificate() == h.result.Certificate

	// The website status code returned is the same status code as the status code of the random wildcard
	IsFallbackStatusCode := parent.HasResult() && h.result.HttpStatus == parent.HttpStatus()

	// The website title is the same as the title using the random wildcard domain
	IsFallbackTitle := parent.HasResult() && h.result.HttpTitle == parent.HttpTitle()

	// The website redirect is the same as the redirect using the random wildcard domain
	IsFallbackRedirect := parent.HasResult() && h.result.HttpRedirect == parent.HttpRedirect() && h.result.HttpRedirect != ""

	if IsValidSpecificCert || (IsValidCert && (!IsFallBackCertificate || !IsFallbackStatusCode || !IsFallbackTitle || !IsFallbackRedirect)) {
		row := NewRow(h.FQDN, Pointer(IsValidCert), Pointer(h.result.HttpStatus), h.result.HttpTitle, Pointer(h.result.HttpRedirect), nil)
		row.DNS = dnsStateFor(gctx, c.Target, h.FQDN)
		table.AddRow(row)
	}

	// When the literal hostname probe failed but an alternative encoding
	// succeeded with a certificate valid for this FQDN, surface each such
	// variant as its own row.
	if h.result.SNIresult != nil {
		for variant, serial := range h.result.EncodingVariants {
			cert, ok := gctx.Certificates[serial]
			if !ok || gctx.IsReflectedCertificate(serial) || !helpers.DNSDomainInArray(helpers.CertHostnames(cert), h.FQDN) {
				continue
			}
			row := NewRow(variant, Pointer(true), nil, "", nil, nil)
			row.DNS = dnsStateFor(gctx, c.Target, h.FQDN)
			table.AddRow(row)
		}
	}
}
