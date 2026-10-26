package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// newTestResolver builds a hostResolver with an injectable lookup function so
// tests never touch the network.
func newTestResolver(lookup func(ctx context.Context, hostname string) ([]net.IP, error)) *hostResolver {
	r := &hostResolver{
		cache:    make(map[string]resolveResult),
		addChan:  make(chan string, 16),
		stopChan: make(chan struct{}),
		lookup:   lookup,
	}
	go r.backgroundResolver()
	return r
}

func TestResolve_CachesFailureWithError(t *testing.T) {
	lookupErr := errors.New("nxdomain")
	calls := 0
	r := newTestResolver(func(ctx context.Context, hostname string) ([]net.IP, error) {
		calls++
		return nil, lookupErr
	})
	defer r.Stop()

	_, err := r.Resolve("gone.example.com")
	if !errors.Is(err, lookupErr) {
		t.Fatalf("expected lookup error, got %v", err)
	}
	// Second lookup must hit the cache and return the same error.
	_, err = r.Resolve("gone.example.com")
	if !errors.Is(err, lookupErr) {
		t.Fatalf("expected cached error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected lookup to run once, ran %d times", calls)
	}
}

func TestResolve_CachesSuccess(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	calls := 0
	r := newTestResolver(func(ctx context.Context, hostname string) ([]net.IP, error) {
		calls++
		return []net.IP{ip}, nil
	})
	defer r.Stop()

	ips, err := r.Resolve("ok.example.com")
	if err != nil || len(ips) != 1 || !ips[0].Equal(ip) {
		t.Fatalf("unexpected first result: %v %v", ips, err)
	}
	ips, err = r.Resolve("ok.example.com")
	if err != nil || len(ips) != 1 || !ips[0].Equal(ip) {
		t.Fatalf("unexpected cached result: %v %v", ips, err)
	}
	if calls != 1 {
		t.Fatalf("expected lookup to run once, ran %d times", calls)
	}
}

func TestBackgroundResolver_CachesFailure(t *testing.T) {
	lookupErr := errors.New("servfail")
	r := newTestResolver(func(ctx context.Context, hostname string) ([]net.IP, error) {
		return nil, lookupErr
	})
	defer r.Stop()

	if err := r.AddHostname("bg.example.com"); err != nil {
		t.Fatalf("AddHostname failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.RLock()
		_, ok := r.cache["bg.example.com"]
		r.mu.RUnlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background lookup was not cached in time")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := r.Resolve("bg.example.com"); !errors.Is(err, lookupErr) {
		t.Fatalf("expected cached failure from background lookup, got %v", err)
	}
}

func TestStop_IdempotentAndUnblocksAddHostname(t *testing.T) {
	r := newTestResolver(func(ctx context.Context, hostname string) ([]net.IP, error) {
		return nil, nil
	})
	r.Stop()
	r.Stop() // must not panic

	// Give the background goroutine time to observe the stop so the select
	// in AddHostname deterministically takes the stop case.
	time.Sleep(10 * time.Millisecond)
	if err := r.AddHostname("late.example.com"); err == nil {
		t.Fatal("AddHostname after Stop must return an error")
	}
}