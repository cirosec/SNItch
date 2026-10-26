package crtlog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestCrtName_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"sub":"www.example.com"},{"sub":"api.example.com"}]`))
	}))
	defer srv.Close()

	entries, err := requestCrtName(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 || entries[0].Sub != "www.example.com" || entries[1].Sub != "api.example.com" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestRequestCrtName_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := requestCrtName(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected the status code in the error, got %v", err)
	}
}

func TestRequestCrtName_BodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An oversized body must be truncated at crtMaxBodySize instead of
		// being fully buffered, so the truncated JSON fails to parse.
		_, _ = w.Write([]byte(`[{"sub":"`))
		chunk := strings.Repeat("a", 64*1024)
		for i := 0; i < int(crtMaxBodySize)/(64*1024)+2; i++ {
			_, _ = w.Write([]byte(chunk))
		}
	}))
	defer srv.Close()

	_, err := requestCrtName(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected a parse error for the truncated oversized body")
	}
	if !strings.Contains(err.Error(), "failed to parse crt.name response") {
		t.Fatalf("expected a parse failure, got %v", err)
	}
}

func TestNewCrtLog_UnwritablePath_NoCacheMode(t *testing.T) {
	// A regular file as the database directory makes rosedb.Open fail; the
	// scan must degrade to no-cache mode instead of panicking.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	db := NewCrtLog(file)
	if db == nil {
		t.Fatal("expected a no-op cache instance, got nil")
	}
	if db.db != nil {
		t.Fatal("expected a nil db handle in no-cache mode")
	}
	db.Close() // must not panic
}

func TestCrtLogDb_CacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db := NewCrtLog(dir)
	defer db.Close()
	if db.db == nil {
		t.Fatal("expected a real db handle for a writable path")
	}
	if err := db.db.Put([]byte("cached.example"), []byte("a.example,b.example")); err != nil {
		t.Fatal(err)
	}
	got, err := db.Get(context.Background(), "cached.example", "")
	if err != nil {
		t.Fatalf("cache hit must not hit the network: %v", err)
	}
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("unexpected cached entries: %v", got)
	}
}