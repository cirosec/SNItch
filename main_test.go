package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

type stubResolver struct{}

func (stubResolver) Resolve(hostname string) ([]net.IP, error) {
	return nil, &net.DNSError{Err: "no such host", Name: hostname}
}
func (stubResolver) AddHostname(hostname string) error { return nil }
func (stubResolver) Stop()                             {}

// resolvingStub returns canned IPs for known hostnames and fails like
// stubResolver for anything else, so the hostname-resolution success path of
// EnsureIP/EnsureIpAndPort can be exercised without network access.
type resolvingStub map[string][]net.IP

func (r resolvingStub) Resolve(hostname string) ([]net.IP, error) {
	if ips, ok := r[hostname]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: hostname}
}
func (resolvingStub) AddHostname(hostname string) error { return nil }
func (resolvingStub) Stop()                             {}

var testResolveIPs = []net.IP{
	net.ParseIP("192.0.2.10"),
	net.ParseIP("2001:db8::10"),
}

func TestEnsureIpAndPort_HostnameResolution(t *testing.T) {
	stub := resolvingStub{"example.test": testResolveIPs}
	got, hostname := EnsureIpAndPort(stub, "example.test")
	want := []string{"192.0.2.10:443", "[2001:db8::10]:443"}
	if len(got) != len(want) {
		t.Fatalf("EnsureIpAndPort(example.test) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("EnsureIpAndPort(example.test)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if hostname != "example.test" {
		t.Errorf("EnsureIpAndPort(example.test) hostname = %q, want %q", hostname, "example.test")
	}
}

func TestEnsureIpAndPort_HostnameWithPort(t *testing.T) {
	stub := resolvingStub{"example.test": testResolveIPs[:1]}
	got, hostname := EnsureIpAndPort(stub, "example.test:8443")
	want := []string{"192.0.2.10:8443"}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("EnsureIpAndPort(example.test:8443) = %v, want %v", got, want)
	}
	if hostname != "example.test" {
		t.Errorf("EnsureIpAndPort(example.test:8443) hostname = %q, want %q", hostname, "example.test")
	}
}

func TestEnsureIpAndPort_UnresolvedHostnameKeptAsHostname(t *testing.T) {
	got, hostname := EnsureIpAndPort(stubResolver{}, "missing.test")
	if len(got) != 0 {
		t.Errorf("EnsureIpAndPort(missing.test) = %v, want no targets", got)
	}
	if hostname != "missing.test" {
		t.Errorf("EnsureIpAndPort(missing.test) hostname = %q, want missing.test (kept for enumeration)", hostname)
	}
}

func TestEnsureIpAndPort_UnbracketedIPv6(t *testing.T) {
	// A bare IPv6 literal is accepted and defaults to port 443. Attaching a
	// port requires brackets; the bracketless "addr:port" spelling is itself a
	// valid IPv6 literal and is therefore treated as an address, not an error.
	cases := map[string][]string{
		"2001:db8::1":      {"[2001:db8::1]:443"},
		"2001:db8::1:8443": {"[2001:db8::1:8443]:443"},
	}
	for input, want := range cases {
		got, _ := EnsureIpAndPort(stubResolver{}, input)
		if len(got) != len(want) {
			t.Errorf("EnsureIpAndPort(%q) = %v, want %v", input, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("EnsureIpAndPort(%q)[%d] = %q, want %q", input, i, got[i], want[i])
			}
		}
	}
}

func TestProcessTargetHostInputs_MergesAndDeduplicates(t *testing.T) {
	targetsFile := filepath.Join(t.TempDir(), "targets.txt")
	hostsFile := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(targetsFile, []byte("192.0.2.1:443\n# comment\n\n192.0.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsFile, []byte("alpha.test\nbeta.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stub := resolvingStub{"gamma.test": testResolveIPs[:1]}
	targets, hosts := ProcessTargetHostInputs(stub, targetsFile, "192.0.2.1:8443, 10.0.0.0/30", hostsFile, "alpha.test,beta.test", "gamma.test")

	wantTargets := []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.1:8443", "10.0.0.0:443", "10.0.0.1:443", "10.0.0.2:443", "10.0.0.3:443", "192.0.2.10:443"}
	if len(targets) != len(wantTargets) {
		t.Fatalf("targets = %v, want %v", targets, wantTargets)
	}
	for i := range wantTargets {
		if targets[i] != wantTargets[i] {
			t.Errorf("targets[%d] = %q, want %q", i, targets[i], wantTargets[i])
		}
	}

	// File, inline and positional hostnames merge and dedupe; the resolved
	// positional domain target contributes its hostname too.
	wantHosts := []string{"alpha.test", "beta.test", "gamma.test"}
	if len(hosts) != len(wantHosts) {
		t.Fatalf("hosts = %v, want %v", hosts, wantHosts)
	}
	for i := range wantHosts {
		if hosts[i] != wantHosts[i] {
			t.Errorf("hosts[%d] = %q, want %q", i, hosts[i], wantHosts[i])
		}
	}
}

func TestProcessTargetHostInputs_MissingFileFailsCleanly(t *testing.T) {
	targets, hosts := ProcessTargetHostInputs(stubResolver{}, "/nonexistent/targets", "", "", "", "")
	if targets != nil || hosts != nil {
		t.Errorf("expected nil results for a missing file, got %v, %v", targets, hosts)
	}
}

func TestValidateScanParams(t *testing.T) {
	valid := [][3]int{{1, 1, 1}, {50, 10, 2}, {1000, 60, 99}}
	for _, v := range valid {
		if err := validateScanParams(v[0], v[1], v[2]); err != nil {
			t.Errorf("validateScanParams(%v) = %v, want nil", v, err)
		}
	}
	invalid := [][3]int{{0, 10, 2}, {-1, 10, 2}, {10, 0, 2}, {10, -5, 2}, {10, 10, 0}, {10, 10, -3}}
	for _, v := range invalid {
		if err := validateScanParams(v[0], v[1], v[2]); err == nil {
			t.Errorf("validateScanParams(%v) = nil, want an error", v)
		}
	}
}

func TestEnsureIpAndPort(t *testing.T) {
	cases := map[string]struct {
		want     []string
		hostname string
	}{
		"1.2.3.4":                 {[]string{"1.2.3.4:443"}, ""},
		"1.2.3.4:8443":            {[]string{"1.2.3.4:8443"}, ""},
		"[2001:db8::1]":           {[]string{"[2001:db8::1]:443"}, ""},
		"[2001:db8::1]:8443":      {[]string{"[2001:db8::1]:8443"}, ""},
		"192.168.1.1:443":         {[]string{"192.168.1.1:443"}, ""},
		"192.168.1.1:notaport":    {nil, ""},
		"192.168.1.1:0":           {nil, ""},
		"192.168.1.1:65536":       {nil, ""},
		"192.168.1.1:65535":       {[]string{"192.168.1.1:65535"}, ""},
		"192.168.1.1:192.168.1.1": {nil, ""},
	}
	for input, want := range cases {
		got, hostname := EnsureIpAndPort(stubResolver{}, input)
		if len(got) != len(want.want) {
			t.Errorf("EnsureIpAndPort(%q) = %v, want %v", input, got, want.want)
			continue
		}
		for i := range got {
			if got[i] != want.want[i] {
				t.Errorf("EnsureIpAndPort(%q) = %v, want %v", input, got, want.want)
			}
		}
		if hostname != want.hostname {
			t.Errorf("EnsureIpAndPort(%q) hostname = %q, want %q", input, hostname, want.hostname)
		}
	}
}

func TestTargetFormatter_CIDR(t *testing.T) {
	targets, hosts := targetFormatter(stubResolver{}, []string{"192.168.100.0/24"})
	if len(targets) != 256 {
		t.Errorf("expected 256 targets from a /24, got %d", len(targets))
	}
	if targets[0] != "192.168.100.0:443" || targets[255] != "192.168.100.255:443" {
		t.Errorf("unexpected expansion bounds: %s .. %s", targets[0], targets[255])
	}
	if len(hosts) != 0 {
		t.Errorf("expected no hostnames from a CIDR, got %v", hosts)
	}
}

func TestTargetFormatter_SkipsBadCIDRsWithoutAborting(t *testing.T) {
	targets, _ := targetFormatter(stubResolver{}, []string{
		"10.0.0.0/8",
		"10.0.0.0/24:abc",
		"not/a/cidr",
		"192.168.50.0/24",
	})
	if len(targets) != 256 {
		t.Errorf("expected the valid /24 to survive (256 targets), got %d: %v", len(targets), targets)
	}
	for _, target := range targets {
		if target[:7] != "192.168" {
			t.Errorf("unexpected target from bad CIDR: %s", target)
		}
	}
}
