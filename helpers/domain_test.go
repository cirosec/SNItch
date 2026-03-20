package helpers

import "testing"

func TestDomainLevelSimple(t *testing.T) {
	label, prefix := GetLabelByLevelFromFQDN("cirosec.de", 0)
	expectedLabel := ""
	expectedPrefix := "cirosec.de"
	if label != expectedLabel {
		t.Errorf("Label result: %v; Label expected: %v", label, expectedLabel)
	}
	if prefix != expectedPrefix {
		t.Errorf("Prefix result: %v; Prefix expected: %v", prefix, expectedPrefix)

	}
}
func TestDomainLevelSimpleTwo(t *testing.T) {
	label, prefix := GetLabelByLevelFromFQDN("lol.cirosec.de", 0)
	expectedLabel := ""
	expectedPrefix := "cirosec.de"
	if label != expectedLabel {
		t.Errorf("Label result: %v; Label expected: %v", label, expectedLabel)
	}
	if prefix != expectedPrefix {
		t.Errorf("Prefix result: %v; Prefix expected: %v", prefix, expectedPrefix)

	}
}

func TestDomainLevelSubdomain(t *testing.T) {
	label, prefix := GetLabelByLevelFromFQDN("lol.cirosec.de", 1)
	expectedLabel := "lol"
	expectedPrefix := "cirosec.de"
	if label != expectedLabel {
		t.Errorf("Label result: %v; Label expected: %v", label, expectedLabel)
	}
	if prefix != expectedPrefix {
		t.Errorf("Prefix result: %v; Prefix expected: %v", prefix, expectedPrefix)
	}
}

func TestDomainLevelDoubleSubdomain(t *testing.T) {
	label, prefix := GetLabelByLevelFromFQDN("foo.bar.cirosec.de", 1)
	expectedLabel := "bar"
	expectedPrefix := "cirosec.de"
	if label != expectedLabel {
		t.Errorf("[1] Label result: %v; Label expected: %v", label, expectedLabel)
	}
	if prefix != expectedPrefix {
		t.Errorf("[1] Prefix result: %v; Prefix expected: %v", prefix, expectedPrefix)
	}

	label, prefix = GetLabelByLevelFromFQDN("foo.bar.cirosec.de", 2)
	expectedLabel = "foo"
	expectedPrefix = "bar.cirosec.de"
	if label != expectedLabel {
		t.Errorf("[2] Label result: %v; Label expected: %v", label, expectedLabel)
	}
	if prefix != expectedPrefix {
		t.Errorf("[2] Prefix result: %v; Prefix expected: %v", prefix, expectedPrefix)
	}
}

func TestFQDNToSLD(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"foo.co.uk", "foo.co.uk"},
		{"bar.foo.co.uk", "foo.co.uk"},
		{"example.com.au", "example.com.au"},
		{"sub.example.com.au", "example.com.au"},
		{"*.example.com", "example.com"},
		{"*.foo.co.uk", "foo.co.uk"},
	}
	for _, tt := range tests {
		result, err := FQDNToSLD(tt.input)
		if err != nil {
			t.Errorf("FQDNToSLD(%q) returned error: %v", tt.input, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("FQDNToSLD(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGetLabelByLevelMultiPartTLD(t *testing.T) {
	// level 0: should return the SLD (effective TLD+1)
	label, prefix := GetLabelByLevelFromFQDN("sub.example.co.uk", 0)
	if label != "" {
		t.Errorf("Label result: %v; expected empty", label)
	}
	if prefix != "example.co.uk" {
		t.Errorf("Prefix result: %v; expected example.co.uk", prefix)
	}

	// level 1: should return the subdomain label above the SLD
	label, prefix = GetLabelByLevelFromFQDN("sub.example.co.uk", 1)
	if label != "sub" {
		t.Errorf("Label result: %v; expected sub", label)
	}
	if prefix != "example.co.uk" {
		t.Errorf("Prefix result: %v; expected example.co.uk", prefix)
	}

	// deeper: foo.bar.example.co.uk
	label, prefix = GetLabelByLevelFromFQDN("foo.bar.example.co.uk", 1)
	if label != "bar" {
		t.Errorf("Label result: %v; expected bar", label)
	}
	if prefix != "example.co.uk" {
		t.Errorf("Prefix result: %v; expected example.co.uk", prefix)
	}

	label, prefix = GetLabelByLevelFromFQDN("foo.bar.example.co.uk", 2)
	if label != "foo" {
		t.Errorf("Label result: %v; expected foo", label)
	}
	if prefix != "bar.example.co.uk" {
		t.Errorf("Prefix result: %v; expected bar.example.co.uk", prefix)
	}
}
