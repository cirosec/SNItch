package helpers

import "testing"

func containsVariant(variants []string, want string) bool {
	for _, v := range variants {
		if v == want {
			return true
		}
	}
	return false
}

func assertUnique(t *testing.T, variants []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, v := range variants {
		if seen[v] {
			t.Fatalf("duplicate variant %q in %v", v, variants)
		}
		seen[v] = true
	}
}

func TestEncodingVariantsASCII(t *testing.T) {
	variants := EncodingVariants("example.com")
	assertUnique(t, variants)
	if !containsVariant(variants, "example.com.") {
		t.Errorf("expected trailing-dot variant, got %v", variants)
	}
	if !containsVariant(variants, "EXAMPLE.COM") {
		t.Errorf("expected uppercase variant, got %v", variants)
	}
	if containsVariant(variants, "example.com") {
		t.Errorf("input must be excluded, got %v", variants)
	}
}

func TestEncodingVariantsPunycodeToUnicode(t *testing.T) {
	variants := EncodingVariants("xn--bcher-kva.example")
	assertUnique(t, variants)
	if !containsVariant(variants, "bücher.example") {
		t.Errorf("expected unicode counterpart, got %v", variants)
	}
}

func TestEncodingVariantsUnicodeToALabel(t *testing.T) {
	variants := EncodingVariants("bücher.example")
	assertUnique(t, variants)
	if !containsVariant(variants, "xn--bcher-kva.example") {
		t.Errorf("expected A-label counterpart, got %v", variants)
	}
}

func TestEncodingVariantsTrailingDotInput(t *testing.T) {
	variants := EncodingVariants("example.com.")
	assertUnique(t, variants)
	if containsVariant(variants, "example.com.") {
		t.Errorf("input must be excluded, got %v", variants)
	}
	if !containsVariant(variants, "EXAMPLE.COM") {
		t.Errorf("expected uppercase variant, got %v", variants)
	}
}
