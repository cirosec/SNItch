package whois

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type countingQuery struct {
	mu      sync.Mutex
	calls   map[string]int
	failFor map[string]bool
}

func (c *countingQuery) query(ip string, timeout time.Duration) (*WHOISinfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[ip]++
	if c.failFor[ip] {
		return nil, errors.New("whois unavailable")
	}
	return &WHOISinfo{Name: "Test Net", Range: "192.0.2.0/24"}, nil
}

func newTestCache(q *countingQuery) *WHOISCache {
	w := NewWHOISCache()
	w.query = q.query
	return w
}

// A failed lookup must be remembered as failed: neither Get nor Query may
// re-query the same IP within a run.
func TestWHOISCache_FailedLookupsAreNotRequeried(t *testing.T) {
	q := &countingQuery{calls: map[string]int{}, failFor: map[string]bool{"10.0.0.1": true}}
	w := newTestCache(q)

	if rec := w.Get("10.0.0.1"); rec != nil {
		t.Fatalf("expected nil record for failed lookup, got %+v", rec)
	}
	if rec := w.Get("10.0.0.1"); rec != nil {
		t.Fatalf("expected nil record on second Get, got %+v", rec)
	}
	w.Query(context.Background(), []string{"10.0.0.1"})
	if q.calls["10.0.0.1"] != 1 {
		t.Fatalf("failed IP was queried %d times, expected exactly 1", q.calls["10.0.0.1"])
	}
}

func TestWHOISCache_SuccessfulLookupsAreCached(t *testing.T) {
	q := &countingQuery{calls: map[string]int{}, failFor: map[string]bool{}}
	w := newTestCache(q)

	rec := w.Get("192.0.2.1")
	if rec == nil || rec.Name != "Test Net" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec2 := w.Get("192.0.2.1"); rec2 != rec {
		t.Fatalf("expected the cached record, got %+v", rec2)
	}
	if q.calls["192.0.2.1"] != 1 {
		t.Fatalf("IP was queried %d times, expected exactly 1", q.calls["192.0.2.1"])
	}
}

// Query must skip IPs already known (success or failure) and not re-dial them.
func TestWHOISCache_QuerySkipsKnownIPs(t *testing.T) {
	q := &countingQuery{calls: map[string]int{}, failFor: map[string]bool{"10.0.0.1": true}}
	w := newTestCache(q)

	w.Query(context.Background(), []string{"192.0.2.1", "10.0.0.1"})
	w.Query(context.Background(), []string{"192.0.2.1", "10.0.0.1"})
	if q.calls["192.0.2.1"] != 1 || q.calls["10.0.0.1"] != 1 {
		t.Fatalf("expected each IP queried once, got success=%d failure=%d",
			q.calls["192.0.2.1"], q.calls["10.0.0.1"])
	}
	if rec := w.Get("10.0.0.1"); rec != nil {
		t.Fatalf("expected nil record for the failed IP, got %+v", rec)
	}
}