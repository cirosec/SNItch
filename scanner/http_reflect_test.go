package scanner

import "testing"

func TestReflectsHost(t *testing.T) {
	if !reflectsHost("https://rand123.example/sonicui/7/login/", "rand123.example") {
		t.Fatal("expected reflected host to be detected")
	}
	if !reflectsHost("https://RAND123.EXAMPLE/x", "rand123.example") {
		t.Fatal("expected case-insensitive detection")
	}
	if reflectsHost("https://real.example/login", "rand123.example") {
		t.Fatal("a distinct redirect host must not be treated as reflection")
	}
	if reflectsHost("", "rand123.example") || reflectsHost("https://x/", "") {
		t.Fatal("empty inputs must not be treated as reflection")
	}
}
