package reverseip

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cirosec/snitch/debug"
)

// A single IP returning far more names than the old channel buffer (8 per IP)
// used to deadlock the producers. The collector pattern must handle it.
func TestCollectPTRs_ManyNamesPerIP(t *testing.T) {
	lookup := func(_ context.Context, addr string) ([]string, error) {
		if addr == "10.0.0.1" {
			names := make([]string, 1000)
			for i := range names {
				names[i] = fmt.Sprintf("host-%d.example.com.", i)
			}
			return names, nil
		}
		return nil, fmt.Errorf("no PTR record")
	}

	done := make(chan []string, 1)
	go func() {
		done <- collectPTRs(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, lookup, func(string) bool { return false }, debug.NopLogger())
	}()

	select {
	case got := <-done:
		if len(got) != 1000 {
			t.Errorf("expected 1000 hostnames, got %d", len(got))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("collectPTRs deadlocked")
	}
}

func TestCollectPTRs_FilterAndDedup(t *testing.T) {
	lookup := func(_ context.Context, addr string) ([]string, error) {
		switch addr {
		case "10.0.0.1":
			return []string{"dup.example.com.", "dup.example.com.", "evil.attacker.com.", "ok.example.com."}, nil
		case "10.0.0.2":
			return []string{"ok.example.com.", "second.example.com."}, nil
		}
		return nil, fmt.Errorf("no PTR record")
	}

	got := collectPTRs(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, lookup,
		func(name string) bool { return name == "evil.attacker.com" }, debug.NopLogger())

	if len(got) != 3 {
		t.Fatalf("expected 3 filtered+deduped hostnames, got %d: %v", len(got), got)
	}
	if len(unique(got)) != len(got) {
		t.Errorf("expected no duplicates in results, got %v", got)
	}
	for _, want := range []string{"dup.example.com", "ok.example.com", "second.example.com"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q in results, got %v", want, got)
		}
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
