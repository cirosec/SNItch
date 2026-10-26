package scan

import (
	"regexp"
	"time"

	"github.com/cirosec/snitch/helpers"
)

// InternalIgnoredHosts contains hosts that are automatically ignored during scans.
// These are typically CDN/proxy certificate domains that pollute results.
var InternalIgnoredHosts = []string{
	"*.cloudflaressl.com",
	"*.your-server.de",
	"*.netlify.com",
	"*.cloudflare.com",
	"*.netlify.app",
	"*.t-ipconnect.de",
	"*.versanet.de",
	"*.akamaitechnologies.com",
}

type ScanConfig struct {
	IgnoredHosts    []string // User-provided ignored hosts (displayed in output)
	RequiredHosts   []regexp.Regexp
	ParallelWorkers int
	UsePTR          bool
	UseCRTLog       bool
	CrtLogDB        string // Path to the crt.name local cache directory
	MaxEpochs       int
	DisableRecon    bool
	NoIPasSNI       bool          // Disables sending the target IP as SNI value (non-RFC compliant check)
	NoPlainHTTP     bool          // Disables plaintext HTTP probing of the target IP (on the HTTP port and the target's TLS port)
	PlainHTTPPort   string        // Port used for plaintext HTTP probing (default 80)
	SearchHeaders   bool          // Enables broader search for domains/URLs in HTTP response headers
	Timeout         time.Duration // Global timeout for network operations
}

// AllIgnoredHosts returns both user-provided and internal ignored hosts for filtering.
func (c *ScanConfig) AllIgnoredHosts() []string {
	all := make([]string, 0, len(c.IgnoredHosts)+len(InternalIgnoredHosts))
	all = append(all, c.IgnoredHosts...)
	all = append(all, InternalIgnoredHosts...)
	return all
}

// HostIsFiltered reports whether host should be excluded from the scan queue:
// either it matches an ignored pattern (user-provided or internal), or
// require-patterns are configured and none of them matches.
func (c *ScanConfig) HostIsFiltered(host string) bool {
	if helpers.WildcardOrFullMatch(host, c.AllIgnoredHosts()) {
		return true
	}
	if len(c.RequiredHosts) > 0 {
		for _, expr := range c.RequiredHosts {
			if expr.MatchString(host) {
				return false
			}
		}
		return true
	}
	return false
}

func NewConfig() *ScanConfig {
	return &ScanConfig{IgnoredHosts: []string{}, RequiredHosts: []regexp.Regexp{}, ParallelWorkers: 4, UsePTR: true, UseCRTLog: true, CrtLogDB: "/tmp/crtlog", MaxEpochs: 5, DisableRecon: false, PlainHTTPPort: "80", Timeout: 10 * time.Second}
}
