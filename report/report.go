// Package report defines the machine-readable (JSONL) representation of a
// scan result. Both the human-readable printer and the JSONL writer are fed
// from the same row data, so the two outputs cannot diverge.
package report

// Record type discriminators, emitted in the "type" field of every record.
const (
	TypeConfig      = "config"
	TypeCertificate = "certificate"
	TypeHost        = "host"
	TypeIP          = "ip"
	TypeSummary     = "summary"
)

// Config is the first record of a run. It captures the effective scan input.
type Config struct {
	Type          string   `json:"type"`
	Version       string   `json:"version"`
	Targets       []string `json:"targets"`
	Hosts         []string `json:"hosts"`
	IgnoredHosts  []string `json:"ignored_hosts,omitempty"`
	RequiredHosts []string `json:"required_hosts,omitempty"`
	DNSServer     string   `json:"dns_server,omitempty"`
}

// Certificate describes one observed certificate and where it was seen. Names
// holds the hostnames the certificate identifies (DNS SANs, CN, IP SANs); Emails
// and Organizations carry the certificate's identity metadata, which is often
// the only place a device vendor's domain appears.
type Certificate struct {
	Type          string   `json:"type"`
	Serial        string   `json:"serial"`
	NotAfter      string   `json:"not_after"`
	Expired       bool     `json:"expired"`
	Names         []string `json:"names"`
	Emails        []string `json:"emails,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	Targets       []string `json:"targets"`
}

// Host is one displayed table row: a hostname validated against a target.
// Hostname is empty for the "(EMPTY SNI)" fallback row; AlternateText carries
// the human label used for the empty-SNI and IP-as-SNI pseudo-hosts.
type Host struct {
	Type          string `json:"type"`
	Target        string `json:"target"`
	Hostname      string `json:"hostname,omitempty"`
	AlternateText string `json:"alternate_text,omitempty"`
	Wildcard      bool   `json:"wildcard,omitempty"`
	// DNS is one of "", "resolves_to_target", "resolves_elsewhere",
	// "unresolved" or "unknown". Empty means the value is not applicable.
	DNS          string `json:"dns,omitempty"`
	CertValid    *bool  `json:"cert_valid,omitempty"`
	HTTPStatus   *int   `json:"http_status,omitempty"`
	HTTPTitle    string `json:"http_title,omitempty"`
	HTTPRedirect string `json:"http_redirect,omitempty"`
	// PlainHTTPTLS is true when the row was discovered by the plaintext-HTTP
	// probe against the target's TLS port rather than the configured HTTP port.
	PlainHTTPTLS bool `json:"plain_http_tls,omitempty"`
}

// IP describes one observed target IP and its WHOIS allocation. Exactly one
// record is emitted per unique IP.
type IP struct {
	Type  string `json:"type"`
	IP    string `json:"ip"`
	Name  string `json:"name,omitempty"`
	Range string `json:"range,omitempty"`
	// DynamicCertificates is true when the server mints a distinct certificate
	// per SNI value (echoing the requested name), so hostnames discovered on
	// this IP are reflections rather than real vhosts.
	DynamicCertificates bool `json:"dynamic_certificates,omitempty"`
}

// Summary is the final record of a run.
type Summary struct {
	Type           string   `json:"type"`
	Iterations     int      `json:"iterations"`
	Cancelled      bool     `json:"cancelled"`
	UnscannedHosts []string `json:"unscanned_hosts,omitempty"`
}
