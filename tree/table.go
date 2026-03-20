package tree

import (
	"fmt"
	"net"
	"strings"

	"github.com/cirosec/snitch/globalcontext"

	"github.com/fatih/color"
)

type MiniTable struct {
	rows []*MiniRow
}

func NewTable() *MiniTable {
	return &MiniTable{[]*MiniRow{}}
}
func (t *MiniTable) AddRow(r *MiniRow) {
	t.rows = append(t.rows, r)
}

func (t *MiniTable) Print(gctx *globalcontext.GlobalContext, target string) {

	MaxDomainLength := 35
	for _, e := range t.rows {
		MaxDomainLength = max(MaxDomainLength, len(e.hostname))
	}
	fmt.Printf("%"+fmt.Sprint(MaxDomainLength+3)+"s   %s  %s\n", "HOSTNAME", "DNS", "CERT")
	for _, e := range t.rows {
		fmt.Println(e.Stringify(MaxDomainLength, gctx, target))
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

type MiniRow struct {
	hostname      string
	validcrt      *bool
	httpstatus    *int
	httptitle     string
	httpredirect  *string
	alternateText *string
}

func NewRow(hostname string, validcert *bool, httpstatus *int, httptitle string, httpredirect *string, alternateText *string) *MiniRow {
	return &MiniRow{hostname, validcert, httpstatus, httptitle, httpredirect, alternateText}
}
func (r *MiniRow) Stringify(maxHostnameLength int, gctx *globalcontext.GlobalContext, target string) string {
	validCertString := "     "
	if r.validcrt != nil {
		if *r.validcrt {
			validCertString = "✅"
		} else {
			validCertString = "❌"
		}
	}
	httpElement := "     "
	if r.httpstatus != nil {
		if r.httpredirect != nil && len(*r.httpredirect) > 0 {
			truncatedRedirect := truncateString(*r.httpredirect, 80)
			httpElement = fmt.Sprintf("[%s] ➤ %s", HTTPStatusCodeColorer(*r.httpstatus), truncatedRedirect)
		} else {
			truncatedTitle := truncateString(r.httptitle, 60)
			httpElement = fmt.Sprintf("[%s]   %s", HTTPStatusCodeColorer(*r.httpstatus), truncatedTitle)
		}
	}
	dnsElement := "    "
	isSpecialIP := r.alternateText != nil && *r.alternateText == "(IP as SNI)"
	if !strings.HasPrefix(r.hostname, "*") && r.hostname != "" && !isSpecialIP {
		dnsrecords, err := gctx.DNSresolver.Resolve(r.hostname)
		pureTarget, _, errTarget := net.SplitHostPort(target)
		if err != nil || errTarget != nil {
			dnsElement = "❔"
		} else {
			if targetIP := net.ParseIP(pureTarget); targetIP != nil {
				dnsElement = "❌"
				for _, element := range dnsrecords {
					if targetIP.Equal(element) {
						dnsElement = "✅"
						break
					}
				}
			}
		}
	}
	firstElement := r.hostname
	if r.alternateText != nil {
		firstElement = *r.alternateText
	}
	return fmt.Sprintf("%"+fmt.Sprint(maxHostnameLength+3)+"s    %-3s %-4s %s", firstElement, dnsElement, validCertString, httpElement)
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
