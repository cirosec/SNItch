package tree

import (
	"testing"

	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/scanner"
)

func TestNewRootDomain(t *testing.T) {
	r := NewRootDomain()
	if r.Labels == nil {
		t.Fatal("Labels map should be initialized")
	}
	if len(r.Labels) != 0 {
		t.Fatal("Labels map should be empty")
	}
}

func TestNewDomainLabel(t *testing.T) {
	dl := NewDomainLabel("sub.example.com", 1)
	if dl.Labels == nil {
		t.Fatal("Labels map should be initialized")
	}
	if dl.Hostname == nil {
		t.Fatal("Hostname should be set")
	}
}

func TestRootDomain_AddResult_CreatesLabels(t *testing.T) {
	r := NewRootDomain()
	result := &scanner.ScannerHostnameResult{}
	r.AddResult("www.example.com", result)

	if len(r.Labels) != 1 {
		t.Fatalf("expected 1 label, got %d", len(r.Labels))
	}
	if _, ok := r.Labels["example.com"]; !ok {
		t.Fatal("expected label 'example.com'")
	}
}

func TestRootDomain_AddResult_RootResult(t *testing.T) {
	r := NewRootDomain()
	rootResult := &scanner.ScannerRootResult{HttpStatus: 200, HttpTitle: "Test"}
	r.AddResult(".", rootResult)

	if !r.HasResult() {
		t.Fatal("root should have result after adding '.' result")
	}
	if r.HttpStatus() != 200 {
		t.Fatalf("expected HttpStatus 200, got %d", r.HttpStatus())
	}
	if r.HttpTitle() != "Test" {
		t.Fatalf("expected HttpTitle 'Test', got %q", r.HttpTitle())
	}
}

func TestRootDomain_ParentNode_NilResult(t *testing.T) {
	r := NewRootDomain()
	if r.HasResult() {
		t.Fatal("should not have result")
	}
	if r.SNIFallbackCertificate() != "" {
		t.Fatal("expected empty string")
	}
	if r.HttpStatus() != 0 {
		t.Fatal("expected 0")
	}
	if r.HttpTitle() != "" {
		t.Fatal("expected empty string")
	}
	if r.HttpRedirect() != "" {
		t.Fatal("expected empty string")
	}
}

func TestDomainLabel_ParentNode_NilResult(t *testing.T) {
	dl := NewDomainLabel("example.com", 0)
	if dl.HasResult() {
		t.Fatal("should not have result")
	}
	if dl.SNIFallbackCertificate() != "" {
		t.Fatal("expected empty string")
	}
	if dl.HttpStatus() != 0 {
		t.Fatal("expected 0")
	}
}

func TestRootDomain_AddResult_MultipleHostnames(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("a.example.com", &scanner.ScannerHostnameResult{})
	r.AddResult("b.example.com", &scanner.ScannerHostnameResult{})
	r.AddResult("c.other.com", &scanner.ScannerHostnameResult{})

	if len(r.Labels) != 2 {
		t.Fatalf("expected 2 root labels, got %d", len(r.Labels))
	}
	if labelCount := len(r.Labels["example.com"].Labels); labelCount != 2 {
		t.Fatalf("expected 2 example.com labels, got %d", labelCount)
	}
}

func TestRootDomain_AddResult_MultipleMultiLabelTLDHostnames(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("a.example.com.sg", &scanner.ScannerHostnameResult{})
	r.AddResult("b.example.com.sg", &scanner.ScannerHostnameResult{})
	r.AddResult("c.other.com.sg", &scanner.ScannerHostnameResult{})

	if len(r.Labels) != 2 {
		t.Fatalf("expected 2 root labels, got %d", len(r.Labels))
	}
	if labelCount := len(r.Labels["example.com.sg"].Labels); labelCount != 2 {
		t.Fatalf("expected 2 example.com.sg labels, got %d", labelCount)
	}
}

func TestRootDomain_AddResult_EmptyDomain(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("", &scanner.ScannerHostnameResult{})
	if len(r.Labels) != 0 {
		t.Fatal("empty hostname should not create labels")
	}
}

func TestRootDomain_AddResult_DeepSubdomains(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("a.b.c.d.example.com", &scanner.ScannerHostnameResult{})

	label, ok := r.Labels["example.com"]
	if !ok {
		t.Fatal("expected label 'example.com'")
	}
	// d.example.com
	label, ok = label.Labels["d.example.com"]
	if !ok {
		t.Fatal("expected label 'd.example.com'")
	}
	// c.d.example.com
	label, ok = label.Labels["c.d.example.com"]
	if !ok {
		t.Fatal("expected label 'c.d.example.com'")
	}
	// b.c.d.example.com
	label, ok = label.Labels["b.c.d.example.com"]
	if !ok {
		t.Fatal("expected label 'b.c.d.example.com'")
	}
	// a.b.c.d.example.com — each subdomain label gets its own DomainLabel node
	label, ok = label.Labels["a.b.c.d.example.com"]
	if !ok {
		t.Fatal("expected label 'a.b.c.d.example.com'")
	}
	if label.Hostname.FQDN != "a.b.c.d.example.com" {
		t.Fatalf("expected FQDN 'a.b.c.d.example.com', got %q", label.Hostname.FQDN)
	}
	if label.Hostname.result == nil {
		t.Fatal("expected hostname result to be set on deepest label")
	}
}

func TestRootDomain_AddResult_DeepSubdomains_MultiLabelTLD(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("x.y.z.example.co.uk", &scanner.ScannerHostnameResult{})

	label, ok := r.Labels["example.co.uk"]
	if !ok {
		t.Fatal("expected label 'example.co.uk'")
	}
	label, ok = label.Labels["z.example.co.uk"]
	if !ok {
		t.Fatal("expected label 'z.example.co.uk'")
	}
	label, ok = label.Labels["y.z.example.co.uk"]
	if !ok {
		t.Fatal("expected label 'y.z.example.co.uk'")
	}
	// x.y.z.example.co.uk — leaf label
	label, ok = label.Labels["x.y.z.example.co.uk"]
	if !ok {
		t.Fatal("expected label 'x.y.z.example.co.uk'")
	}
	if label.Hostname.FQDN != "x.y.z.example.co.uk" {
		t.Fatalf("expected FQDN 'x.y.z.example.co.uk', got %q", label.Hostname.FQDN)
	}
	if label.Hostname.result == nil {
		t.Fatal("expected hostname result to be set on deepest label")
	}
}

func TestRootDomain_AddResult_WildcardSubdomain(t *testing.T) {
	r := NewRootDomain()
	subResult := &scanner.ScannerSubdomainResult{}
	r.AddResult("*.example.com", subResult)

	label, ok := r.Labels["example.com"]
	if !ok {
		t.Fatal("expected label 'example.com'")
	}
	if !label.HasResult() {
		t.Fatal("wildcard result should be set on the domain label")
	}
}

func TestRootDomain_AddResult_WildcardDeepSubdomain(t *testing.T) {
	r := NewRootDomain()
	subResult := &scanner.ScannerSubdomainResult{}
	r.AddResult("*.sub.example.com", subResult)

	label, ok := r.Labels["example.com"]
	if !ok {
		t.Fatal("expected label 'example.com'")
	}
	label, ok = label.Labels["sub.example.com"]
	if !ok {
		t.Fatal("expected label 'sub.example.com'")
	}
	if !label.HasResult() {
		t.Fatal("wildcard result should be set on sub.example.com label")
	}
}

func TestDomainLabel_AddResult_NonMatchingSuffix(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("www.example.com", &scanner.ScannerHostnameResult{})

	label := r.Labels["example.com"]
	ok := label.AddResult("www.other.com", 0, &scanner.ScannerHostnameResult{})
	if ok {
		t.Fatal("AddResult should return false for non-matching suffix")
	}
}

func TestRootDomain_AddResult_SiblingSubdomains(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("a.sub.example.com", &scanner.ScannerHostnameResult{})
	r.AddResult("b.sub.example.com", &scanner.ScannerHostnameResult{})
	r.AddResult("c.other.example.com", &scanner.ScannerHostnameResult{})

	label := r.Labels["example.com"]
	if len(label.Labels) != 2 {
		t.Fatalf("expected 2 sublabels under example.com, got %d", len(label.Labels))
	}
	subLabel := label.Labels["sub.example.com"]
	if subLabel == nil {
		t.Fatal("expected label 'sub.example.com'")
	}
	if len(subLabel.Labels) != 2 {
		t.Fatalf("expected 2 sublabels under sub.example.com, got %d", len(subLabel.Labels))
	}
}

func TestDomainLabel_ParentNode_WithResult(t *testing.T) {
	r := NewRootDomain()
	r.AddResult("*.example.com", &scanner.ScannerSubdomainResult{
		SNIFallbackCertificate: "cert123",
		HttpStatus:             301,
		HttpTitle:              "Redirect",
		HttpRedirect:           "https://example.com",
	})

	label := r.Labels["example.com"]
	if !label.HasResult() {
		t.Fatal("should have result")
	}
	if label.SNIFallbackCertificate() != "cert123" {
		t.Fatalf("expected 'cert123', got %q", label.SNIFallbackCertificate())
	}
	if label.HttpStatus() != 301 {
		t.Fatalf("expected 301, got %d", label.HttpStatus())
	}
	if label.HttpTitle() != "Redirect" {
		t.Fatalf("expected 'Redirect', got %q", label.HttpTitle())
	}
	if label.HttpRedirect() != "https://example.com" {
		t.Fatalf("expected 'https://example.com', got %q", label.HttpRedirect())
	}
}

// The (EMPTY SNI) row must reflect a real no-SNI connection, not the random-SNI
// HTTP probe, and must not be emitted for a hardened server that rejects an
// unknown/random SNI.
func TestRootDomain_Print_EmptySNIRow(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	r := NewRootDomain()
	r.result = &scanner.ScannerRootResult{
		Target:                 "10.0.0.1:443",
		SNIAllowsMissing:       scanner.TriStateTrue,
		SNIDisconnectsOnRandom: scanner.TriStateTrue,
		EmptySNIHttpStatus:     404,
		EmptySNIHttpTitle:      "No SNI",
		EmptySNIHttpRedirect:   "",
		// Random-SNI probe values must NOT leak into the row.
		HttpStatus:   0,
		HttpTitle:    "",
		HttpRedirect: "",
	}

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	rows := table.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.AlternateText == nil || *row.AlternateText != "(EMPTY SNI)" {
		t.Fatalf("expected (EMPTY SNI) row, got %+v", row)
	}
	if row.HTTPStatus == nil || *row.HTTPStatus != 404 {
		t.Fatalf("expected no-SNI HTTP status 404, got %v", row.HTTPStatus)
	}
	if row.HTTPTitle != "No SNI" {
		t.Fatalf("expected no-SNI title, got %q", row.HTTPTitle)
	}
}

// A server that rejects all SNI values (including no/empty SNI and random) is
// hardened and should produce no (EMPTY SNI) row at all.
func TestRootDomain_Print_HardenedNoEmptySNIRow(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	r := NewRootDomain()
	r.result = &scanner.ScannerRootResult{
		Target:                 "10.0.0.1:443",
		SNIAllowsMissing:       scanner.TriStateFalse,
		SNIAllowsEmptyWithExt:  scanner.TriStateFalse,
		SNIDisconnectsOnRandom: scanner.TriStateTrue,
	}

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	if len(table.Rows()) != 0 {
		t.Fatalf("expected no rows for hardened server, got %d", len(table.Rows()))
	}
}

// A hostname revealed by the plaintext-HTTP probe against the target's TLS port
// must surface as its own (HTTP/TLS ...) row.
func TestRootDomain_Print_PlainHTTPTLSRow(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	r := NewRootDomain()
	r.result = &scanner.ScannerRootResult{
		Target:               "10.0.0.1:443",
		PlainHTTPTLSHost:     "10.0.0.1",
		PlainHTTPTLSStatus:   301,
		PlainHTTPTLSRedirect: "https://leak.example/login",
	}

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	rows := table.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.AlternateText == nil || *row.AlternateText != "(HTTP/TLS 10.0.0.1)" {
		t.Fatalf("expected (HTTP/TLS ...) row, got %+v", row)
	}
	if !row.PlainHTTPTLS {
		t.Fatalf("expected PlainHTTPTLS row flag")
	}
	if row.HTTPStatus == nil || *row.HTTPStatus != 301 {
		t.Fatalf("expected status 301, got %v", row.HTTPStatus)
	}
	report_row := row.ToReport("10.0.0.1:443")
	if !report_row.PlainHTTPTLS {
		t.Fatalf("expected plain_http_tls in report record")
	}
}


// A reveal triggered by the Host-less HTTP/1.0 probe must be labeled "(HTTP
// no-host)"; with no host in the request, any hostname in the redirect is the
// server's own configured name.
func TestRootDomain_Print_PlainHTTPNoHostRow(t *testing.T) {
	gctx := globalcontext.NewGlobalContext(dns.NewDNSResolver(""))
	defer gctx.DNSresolver.Stop()

	r := NewRootDomain()
	r.result = &scanner.ScannerRootResult{
		Target:              "10.0.0.1:443",
		PlainHTTPHostNoHost: true,
		PlainHTTPStatus:     301,
		PlainHTTPRedirect:   "https://canonical.example/",
	}

	table := r.BuildTable(gctx, &PrintConfig{Root: r, Target: "10.0.0.1:443"})
	rows := table.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.AlternateText == nil || *row.AlternateText != "(HTTP no-host)" {
		t.Fatalf("expected (HTTP no-host) row, got %+v", row)
	}
}
