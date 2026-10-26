package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/models"
	"github.com/cirosec/snitch/whois"
)

func keyFor(target, host string) models.ScanContextResultKey {
	return models.ScanContextResultKey{Target: target, Host: host}
}

// hostIsFiltered covers --ignore patterns, internal ignore patterns and the
// -r/--require regular expressions.
func TestHostIsFiltered(t *testing.T) {
	ignoreOnly := NewConfig()
	ignoreOnly.IgnoredHosts = []string{"portal.test", "*.internal.test"}

	if ignoreOnly.HostIsFiltered("portal.test") != true {
		t.Error("exact ignore pattern must filter")
	}
	if ignoreOnly.HostIsFiltered("web.internal.test") != true {
		t.Error("wildcard ignore pattern must filter")
	}
	if ignoreOnly.HostIsFiltered("alpha.test") != false {
		t.Error("unmatched host must not be filtered")
	}
	if ignoreOnly.HostIsFiltered("cdn.cloudflaressl.com") != true {
		t.Error("internal ignore patterns must always apply")
	}

	requireOnly := NewConfig()
	requireOnly.RequiredHosts = []regexp.Regexp{*regexp.MustCompile(`^alpha\.`)}

	if requireOnly.HostIsFiltered("alpha.test") != false {
		t.Error("host matching a require pattern must not be filtered")
	}
	if requireOnly.HostIsFiltered("beta.test") != true {
		t.Error("host matching no require pattern must be filtered")
	}

	both := NewConfig()
	both.IgnoredHosts = []string{"*.internal.test"}
	both.RequiredHosts = []regexp.Regexp{*regexp.MustCompile(`\.test$`)}
	if both.HostIsFiltered("web.internal.test") != true {
		t.Error("ignore must win over require")
	}
	if both.HostIsFiltered("other.example") != true {
		t.Error("require mismatch must filter even without ignore match")
	}
}

// ParallelFilterOfflineTargets must keep only targets that accept TCP
// connections, regardless of the worker count.
func TestParallelFilterOfflineTargets(t *testing.T) {
	listenerA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerA.Close()
	listenerB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerB.Close()

	// A closed port on loopback: refused quickly on Linux.
	deadListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, deadPort, _ := net.SplitHostPort(deadListener.Addr().String())
	deadListener.Close()

	targetA := listenerA.Addr().String()
	targetB := listenerB.Addr().String()
	deadTarget := net.JoinHostPort("127.0.0.1", deadPort)

	log := debug.NopLogger()
	got := ParallelFilterOfflineTargets(context.Background(), []string{deadTarget, targetA, targetB}, log, 2*time.Second, 2)

	if len(got) != 2 {
		t.Fatalf("expected 2 online targets, got %v", got)
	}
	// Results are sorted, not in dial-completion order.
	if got[0] != targetA && got[0] != targetB {
		t.Errorf("unexpected target %q", got[0])
	}
	for _, target := range got {
		if target == deadTarget {
			t.Errorf("offline target %q must be filtered out", deadTarget)
		}
	}
}

// selfSignedCertFor creates an in-memory self-signed certificate valid for
// the given SANs.
func selfSignedCertFor(sans []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: sans[0]},
		DNSNames:              sans,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// newSNITLSServer starts a TLS listener that serves one certificate per
// configured hostname (chosen by SNI) and answers each vhost with the given
// status and Location header.
func newSNITLSServer(t *testing.T, vhosts map[string]tls.Certificate, status int, location string) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cert, ok := vhosts[strings.ToLower(hello.ServerName)]; ok {
				return &cert, nil
			}
			return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if location != "" && 300 <= status && status < 400 {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().String()
}

func newTestGlobalContext(t *testing.T) *globalcontext.GlobalContext {
	t.Helper()
	resolver := dns.NewDNSResolver("")
	t.Cleanup(resolver.Stop)
	gctx := globalcontext.NewGlobalContext(resolver)
	gctx.DebugLog = debug.NopLogger()
	gctx.Timeout = 5 * time.Second
	// WHOIS lookups would hit real servers; inject a failing stub query.
	gctx.Whois.SetQueryFunc(func(ip string, timeout time.Duration) (*whois.WHOISinfo, error) {
		return nil, fmt.Errorf("whois disabled in tests")
	})
	return gctx
}

func newTestScanConfig() *ScanConfig {
	config := NewConfig()
	config.Timeout = 5 * time.Second
	config.ParallelWorkers = 4
	config.UseCRTLog = false // keep the scan hermetic
	config.UsePTR = false    // no PTR records for 127.0.0.1 in the test env
	config.MaxEpochs = 2
	return config
}

// The DoScan epoch loop must discover a redirect target in iteration 1 and
// scan it in iteration 2: the first vhost redirects to a second vhost on the
// same server, whose certificate carries both names.
func TestDoScan_DiscoversRedirectHostInNextEpoch(t *testing.T) {
	cert, err := selfSignedCertFor([]string{"first.example.test", "second.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	target := newSNITLSServer(t,
		map[string]tls.Certificate{"first.example.test": cert, "second.example.test": cert},
		http.StatusMovedPermanently, "https://second.example.test/login")

	gctx := newTestGlobalContext(t)
	config := newTestScanConfig()
	manager := DoScan(context.Background(), []string{"first.example.test"}, []string{target}, config, gctx)

	if manager.cancelled {
		t.Fatal("scan was cancelled unexpectedly")
	}
	unscanned := manager.container.GetUnscannedHosts()
	if len(unscanned) != 0 {
		t.Errorf("expected no unscanned hosts after 2 epochs, got %v", unscanned)
	}

	scanned := map[string]bool{}
	for _, host := range manager.container.GetHosts() {
		scanned[host] = true
	}
	if !scanned["second.example.test"] {
		t.Errorf("redirect-discovered host was never queued; hosts = %v", manager.container.GetHosts())
	}
	if _, ok := manager.container.results[keyFor(target, "second.example.test")]; !ok {
		t.Errorf("redirect-discovered host was never scanned; results keys missing %q", "second.example.test")
	}
	if manager.iterations > config.MaxEpochs {
		t.Errorf("scan ran %d iterations, max is %d", manager.iterations, config.MaxEpochs)
	}
}

// With MaxEpochs=1 the redirect target is discovered but never scanned, and
// DoScan must report it as unscanned so the caller can warn.
func TestDoScan_UnscannedHostsReportedWhenEpochsExhausted(t *testing.T) {
	cert, err := selfSignedCertFor([]string{"first.example.test", "second.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	target := newSNITLSServer(t,
		map[string]tls.Certificate{"first.example.test": cert, "second.example.test": cert},
		http.StatusMovedPermanently, "https://second.example.test/login")

	gctx := newTestGlobalContext(t)
	config := newTestScanConfig()
	config.MaxEpochs = 1
	manager := DoScan(context.Background(), []string{"first.example.test"}, []string{target}, config, gctx)

	found := false
	for _, host := range manager.unscannedHosts {
		if host == "second.example.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected second.example.test in unscanned hosts %v", manager.unscannedHosts)
	}
}

// With recon disabled no redirect hostname may be queued at all.
func TestDoScan_DisabledReconIgnoresRedirectHosts(t *testing.T) {
	cert, err := selfSignedCertFor([]string{"first.example.test", "second.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	target := newSNITLSServer(t,
		map[string]tls.Certificate{"first.example.test": cert, "second.example.test": cert},
		http.StatusMovedPermanently, "https://second.example.test/login")

	gctx := newTestGlobalContext(t)
	config := newTestScanConfig()
	config.DisableRecon = true
	manager := DoScan(context.Background(), []string{"first.example.test"}, []string{target}, config, gctx)

	for _, host := range manager.container.GetHosts() {
		if host == "second.example.test" {
			t.Error("redirect-discovered host must not be queued with --no-recon")
		}
	}
}

// The EnqueueAll chunker must split the target list into chunks of 3, so 5
// targets enqueue one chunk of 3 and one chunk of 2 per hostname.
func TestEnqueueAll_ChunksTargets(t *testing.T) {
	config := NewConfig()
	config.ParallelWorkers = 1
	gctx := newTestGlobalContext(t)
	manager := NewScanManager(config, gctx)
	for _, target := range []string{"1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443", "4.4.4.4:443", "5.5.5.5:443"} {
		manager.container.AddTarget(target)
	}

	go manager.EnqueueAll(context.Background(), []string{"host.example"})

	// EnqueueAll does not close the queue; drain exactly the expected number
	// of items with a deadline so the test cannot hang.
	var sizes []int
	deadline := time.After(5 * time.Second)
	for len(sizes) < 2 {
		select {
		case job := <-manager.queue:
			if job.hostname != "host.example" {
				t.Errorf("unexpected hostname %q", job.hostname)
			}
			sizes = append(sizes, len(job.targets))
		case <-deadline:
			t.Fatalf("timed out after %d items; expected 2", len(sizes))
		}
	}
	if sizes[0] != 3 || sizes[1] != 2 {
		t.Errorf("chunk sizes = %v, want [3 2]", sizes)
	}
}