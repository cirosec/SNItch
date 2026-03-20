package scan

import (
	"regexp"
	"time"
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
}

type ScanConfig struct {
	IgnoredHosts    []string // User-provided ignored hosts (displayed in output)
	RequiredHosts   []regexp.Regexp
	ParallelWorkers int
	UsePTR          bool
	UseCRTSH        bool
	CrtshDB         string        // Path to the crt.sh local cache directory
	MaxEpochs       int
	DisableRecon    bool
	NoIPasSNI       bool          // Disables sending the target IP as SNI value (non-RFC compliant check)
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

func NewConfig() *ScanConfig {
	return &ScanConfig{IgnoredHosts: []string{}, RequiredHosts: []regexp.Regexp{}, ParallelWorkers: 4, UsePTR: true, UseCRTSH: true, CrtshDB: "/tmp/crtshdb", MaxEpochs: 5, DisableRecon: false, Timeout: 10 * time.Second}
}
