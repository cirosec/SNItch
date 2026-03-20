package tree

import (
	"fmt"
	"net"
	"strings"

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

func (r *RootDomain) TablePrint(gctx *globalcontext.GlobalContext, c *PrintConfig) {
	ipColor := color.New(color.FgBlack, color.BgWhite).SprintFunc()
	fmt.Println()
	heading := fmt.Sprintf("%50v", c.Target)
	if ip, _, err := net.SplitHostPort(c.Target); err == nil {
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			heading += "  (" + strings.TrimSuffix(names[0], ".") + ")"
		}
	}
	fmt.Print(ipColor(heading) + "\n")

	//Sorting as go can't handle it itself
	keys := make([]string, 0, len(r.Labels))

	for k := range r.Labels {
		keys = append(keys, k)
	}
	helpers.SortDomains(keys)

	table := NewTable()

	//Actually print the result
	r.Print(gctx, c, table)
	for _, value := range keys {
		r.Labels[value].Print(gctx, c, table, r)
	}
	table.Print(gctx, c.Target)
}

func (r *RootDomain) Print(gctx *globalcontext.GlobalContext, c *PrintConfig, table *MiniTable) {
	// gctx attributes are not locked here. This is not a problem, since the scan has already ended. Hence this function is the only one using the data.
	if r.result == nil {
		return
	}
	if r.result.SNIAllowsAny == scanner.TriStateTrue || r.result.SNIAllowsMissing == scanner.TriStateTrue || r.result.SNIAllowsEmpty == scanner.TriStateTrue || r.result.SNIDisconnectsOnRandom == scanner.TriStateTrue {
		table.AddRow(NewRow("", nil, Pointer(r.result.HttpStatus), r.result.HttpTitle, Pointer(r.result.HttpRedirect), Pointer("(EMPTY SNI)")))
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
			table.AddRow(NewRow(c.Target, Pointer(ipInSAN), nil, "", nil, Pointer("(IP as SNI)")))
		}
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
	// Check if the certificate for the random subdomain of this wildcard is the same certificate as the root fallback certificate
	NotAFallbackCertificate := len(s.result.SNIFallbackCertificate) > 0 && c.Root.HasResult() && len(c.Root.SNIFallbackCertificate()) > 0 &&
		s.result.SNIFallbackCertificate != c.Root.SNIFallbackCertificate()

	// Check if the certificate for the random subdomain of this wildcard actually matches the hostname
	CertificateMatchesHostname := s.result.SNIresult == nil && len(s.result.SNIFallbackCertificate) > 0 &&
		helpers.Contains(gctx.Certificates[s.result.SNIFallbackCertificate].DNSNames, "*."+s.DomainPrefix)

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
	if s.result.SNIresult == nil && (CertificateMatchesHostname || ((NotAFallbackCertificate || HTTPResult) && !HTTPFallback)) {
		if HTTPResult {
			table.AddRow(NewRow("*."+s.DomainPrefix, Pointer(CertificateMatchesHostname), Pointer(s.result.HttpStatus), s.result.HttpTitle, Pointer(s.result.HttpRedirect), nil))
		} else {
			table.AddRow(NewRow("*."+s.DomainPrefix, Pointer(CertificateMatchesHostname), nil, "", Pointer(""), nil))
		}
	}
}

func Pointer[T any](d T) *T {
	return &d
}

func (h *FQDN) Print(gctx *globalcontext.GlobalContext, c *PrintConfig, parent ParentNode, table *MiniTable) {
	if h.result == nil {
		return
	}

	// if the certificate used for this domain is valid for the domain
	IsValidCert := len(h.result.Certificate) > 0 && helpers.DNSDomainInArray(gctx.Certificates[h.result.Certificate].DNSNames, h.FQDN)

	// If the domain was explicitly issued a certificate which is not a wildcard certificate
	IsValidSpecificCert := len(h.result.Certificate) > 0 && helpers.Contains(gctx.Certificates[h.result.Certificate].DNSNames, h.FQDN)

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
		table.AddRow(NewRow(h.FQDN, Pointer(IsValidCert), Pointer(h.result.HttpStatus), h.result.HttpTitle, Pointer(h.result.HttpRedirect), nil))
	}
}
