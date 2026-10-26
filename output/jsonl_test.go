package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cirosec/snitch/report"
)

func TestJSONLWriter_OneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteConfig(report.Config{Type: report.TypeConfig, Version: "1.0", Targets: []string{"10.0.0.1:443"}}); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := w.WriteHost(report.Host{Type: report.TypeHost, Target: "10.0.0.1:443", Hostname: "a.example.com"}); err != nil {
		t.Fatalf("write host: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}
	for i, line := range lines {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestJSONLWriter_NilSafe(t *testing.T) {
	var w *JSONLWriter
	if err := w.WriteHost(report.Host{}); err != nil {
		t.Fatalf("nil writer should be a no-op, got %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("nil writer Close should be a no-op, got %v", err)
	}
	if w.Path() != "" {
		t.Fatalf("nil writer Path should be empty")
	}
}

func TestJSONLWriter_OmitsEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteIP(report.IP{Type: report.TypeIP, IP: "10.0.0.1"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()

	out := buf.String()
	if strings.Contains(out, `"name"`) {
		t.Fatalf("empty name should be omitted: %q", out)
	}
	if strings.Contains(out, `"range"`) {
		t.Fatalf("empty range should be omitted: %q", out)
	}
}
