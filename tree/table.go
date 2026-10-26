package tree

import (
	"fmt"

	"github.com/cirosec/snitch/report"
	"github.com/fatih/color"
)

// DNSState describes how a hostname's DNS records relate to the scanned
// target IP. It is computed once, when the row is built, so that both the
// table printer and the JSONL writer use the exact same value.
type DNSState string

const (
	DNSNotApplicable     DNSState = ""
	DNSResolvesToTarget  DNSState = "resolves_to_target"
	DNSResolvesElsewhere DNSState = "resolves_elsewhere"
	DNSUnresolved        DNSState = "unresolved"
)

func (d DNSState) symbol() string {
	switch d {
	case DNSResolvesToTarget:
		return "✅"
	case DNSResolvesElsewhere:
		return "❌"
	case DNSUnresolved:
		return "❔"
	default:
		return "    "
	}
}

type MiniTable struct {
	rows []*MiniRow
}

func NewTable() *MiniTable {
	return &MiniTable{[]*MiniRow{}}
}
func (t *MiniTable) AddRow(r *MiniRow) {
	t.rows = append(t.rows, r)
}

// Rows exposes the built rows, e.g. for serialization to JSONL.
func (t *MiniTable) Rows() []*MiniRow {
	return t.rows
}

func (t *MiniTable) Print() {

	MaxDomainLength := 35
	for _, e := range t.rows {
		MaxDomainLength = max(MaxDomainLength, len(e.Hostname))
	}
	fmt.Printf("%"+fmt.Sprint(MaxDomainLength+3)+"s   %s  %s\n", "HOSTNAME", "DNS", "CERT")
	for _, e := range t.rows {
		fmt.Println(e.Stringify(MaxDomainLength))
	}
}

func PrintLegend() {
	fmt.Println("\n" + "─────────────────────── Legend ───────────────────────")
	fmt.Println("DNS:  ✅=Resolves to target IP  ❌=Resolves elsewhere  ❔=DNS entry not resolved")
	fmt.Println("CERT: ✅=Valid certificate for hostname  ❌=Invalid/missing certificate*")
	fmt.Println("      *No full browser-like certificate validation is performed!")
	// Note that, a valid certificate here implies, that the hostname matches the hostname in the certificate. No other checks are performed!
	// The tool does not differentiate between self-signed and certificates considered valid by major browsers
	// The tool does not really care about the certificate issuer.
}

// MiniRow is one displayed/exported result row. All decisions about DNS
// validity and certificate validity are made when the row is built, so a row
// is pure data and can be rendered multiple ways.
type MiniRow struct {
	Hostname      string
	Wildcard      bool
	AlternateText *string
	DNS           DNSState
	ValidCert     *bool
	HTTPStatus    *int
	HTTPTitle     string
	HTTPRedirect  *string
	PlainHTTPTLS  bool
}

func NewRow(hostname string, validcert *bool, httpstatus *int, httptitle string, httpredirect *string, alternateText *string) *MiniRow {
	return &MiniRow{
		Hostname:      hostname,
		AlternateText: alternateText,
		ValidCert:     validcert,
		HTTPStatus:    httpstatus,
		HTTPTitle:     httptitle,
		HTTPRedirect:  httpredirect,
	}
}

// displayName is the left-most column value: the alternate text if present,
// otherwise the hostname.
func (r *MiniRow) displayName() string {
	if r.AlternateText != nil {
		return *r.AlternateText
	}
	return r.Hostname
}

func (r *MiniRow) Stringify(maxHostnameLength int) string {
	validCertString := "     "
	if r.ValidCert != nil {
		if *r.ValidCert {
			validCertString = "✅"
		} else {
			validCertString = "❌"
		}
	}
	httpElement := "     "
	if r.HTTPStatus != nil {
		if r.HTTPRedirect != nil && len(*r.HTTPRedirect) > 0 {
			truncatedRedirect := truncateString(*r.HTTPRedirect, 80)
			httpElement = fmt.Sprintf("[%s] ➤ %s", HTTPStatusCodeColorer(*r.HTTPStatus), truncatedRedirect)
		} else {
			truncatedTitle := truncateString(r.HTTPTitle, 60)
			httpElement = fmt.Sprintf("[%s]   %s", HTTPStatusCodeColorer(*r.HTTPStatus), truncatedTitle)
		}
	}
	return fmt.Sprintf("%"+fmt.Sprint(maxHostnameLength+3)+"s    %-3s %-4s %s", r.displayName(), r.DNS.symbol(), validCertString, httpElement)
}

// ToReport converts a row into its machine-readable representation. The DNS
// state and HTTP redirect are normalized to stable, color-free values.
func (r *MiniRow) ToReport(target string) report.Host {
	h := report.Host{
		Type:         report.TypeHost,
		Target:       target,
		Hostname:     r.Hostname,
		Wildcard:     r.Wildcard,
		DNS:          string(r.DNS),
		CertValid:    r.ValidCert,
		HTTPStatus:   r.HTTPStatus,
		HTTPTitle:    r.HTTPTitle,
		PlainHTTPTLS: r.PlainHTTPTLS,
	}
	if r.AlternateText != nil {
		h.AlternateText = *r.AlternateText
	}
	if r.HTTPRedirect != nil {
		h.HTTPRedirect = *r.HTTPRedirect
	}
	return h
}

func HTTPStatusCodeColorer(code int) string {
	if code/100 == 2 {
		return color.GreenString(fmt.Sprintf("%3d", code))
	}
	if code/100 == 3 {
		return color.YellowString(fmt.Sprintf("%3d", code))
	}
	if code/100 == 4 {
		return color.RedString(fmt.Sprintf("%3d", code))
	}
	if code/100 == 5 {
		return color.HiRedString(fmt.Sprintf("%3d", code))
	}
	return fmt.Sprintf("%3d", code)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
