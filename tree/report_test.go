package tree

import (
	"testing"

	"github.com/cirosec/snitch/report"
)

func TestMiniRow_ToReport_Hostname(t *testing.T) {
	valid := true
	status := 200
	redirect := ""
	row := NewRow("www.example.com", &valid, &status, "Example", &redirect, nil)
	row.DNS = DNSResolvesToTarget

	h := row.ToReport("10.0.0.1:443")

	if h.Type != report.TypeHost {
		t.Fatalf("expected type %q, got %q", report.TypeHost, h.Type)
	}
	if h.Target != "10.0.0.1:443" || h.Hostname != "www.example.com" {
		t.Fatalf("unexpected target/hostname: %+v", h)
	}
	if h.DNS != string(DNSResolvesToTarget) {
		t.Fatalf("expected DNS state, got %q", h.DNS)
	}
	if h.CertValid == nil || !*h.CertValid {
		t.Fatalf("expected cert valid true")
	}
	if h.HTTPStatus == nil || *h.HTTPStatus != 200 {
		t.Fatalf("expected HTTP status 200")
	}
}

func TestMiniRow_ToReport_AlternateText(t *testing.T) {
	row := NewRow("", nil, nil, "", nil, Pointer("(EMPTY SNI)"))
	h := row.ToReport("10.0.0.1:443")
	if h.AlternateText != "(EMPTY SNI)" {
		t.Fatalf("expected alternate text, got %q", h.AlternateText)
	}
	if h.Hostname != "" {
		t.Fatalf("expected empty hostname, got %q", h.Hostname)
	}
}

func TestMiniRow_ToReport_Wildcard(t *testing.T) {
	row := NewRow("*.example.com", nil, nil, "", Pointer(""), nil)
	row.Wildcard = true
	h := row.ToReport("10.0.0.1:443")
	if !h.Wildcard {
		t.Fatalf("expected wildcard flag")
	}
}
