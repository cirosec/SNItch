package requests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cirosec/snitch/dns"
)

// testResolver is shared by the hermetic tests of this package. Their dial
// targets are loopback IP literals, so no real DNS lookups ever happen.
func testResolver() dns.DNSResolver {
	return dns.NewDNSResolver("")
}

// staticResolver is a dns.DNSResolver that pins every hostname to a fixed IP
// set, so tests can use hostname targets (as the scanner does) without
// touching the system resolver.
type staticResolver struct {
	ips []net.IP
}

func (s staticResolver) Resolve(string) ([]net.IP, error) { return s.ips, nil }
func (s staticResolver) AddHostname(string) error         { return nil }
func (s staticResolver) Stop()                            {}

// loopbackResolver resolves every hostname to 127.0.0.1.
func loopbackResolver() dns.DNSResolver {
	return staticResolver{ips: []net.IP{net.IPv4(127, 0, 0, 1).To4()}}
}

var certSerial uint64

// makeServerCert creates a self-signed serving certificate for the given SAN
// names.
func makeServerCert(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(atomic.AddUint64(&certSerial, 1))),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sniServer is a local TLS server that selects its serving certificate from
// the SNI name in the ClientHello, mirroring the SNI-based virtual hosts this
// tool scans.
type sniServer struct {
	addr     string
	observed chan string // server names offered by connecting clients
}

// newSNIServer starts a TLS server on 127.0.0.1. getCert receives the
// ClientHelloInfo and selects the certificate to serve. Returning (nil, nil)
// makes the server abort the handshake with an unrecognized-name alert, like
// a strict vhost rejecting an unknown name.
func newSNIServer(t *testing.T, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *sniServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sniServer{addr: ln.Addr().String(), observed: make(chan string, 8)}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			select {
			case s.observed <- chi.ServerName:
			default:
			}
			return getCert(chi)
		},
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				sc := tls.Server(conn, cfg)
				_ = sc.Handshake()
			}()
		}
	}()
	return s
}

// seenName returns the next server name the server recorded.
func (s *sniServer) seenName(t *testing.T) string {
	t.Helper()
	select {
	case name := <-s.observed:
		return name
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server to observe a ClientHello")
		return ""
	}
}

// TestMakeSNIRequest_VhostSelection verifies the core mechanism: the crafted
// SNI decides which certificate a vhost-hosting server serves.
func TestMakeSNIRequest_VhostSelection(t *testing.T) {
	certs := map[string]*tls.Certificate{
		"alpha.vhost.example": nil,
		"beta.vhost.example":  nil,
	}
	for name := range certs {
		c := makeServerCert(t, name)
		certs[name] = &c
	}
	fallback := makeServerCert(t, "default.vhost.example")
	srv := newSNIServer(t, func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if cert, ok := certs[chi.ServerName]; ok {
			return cert, nil
		}
		return &fallback, nil
	})

	_, port, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatal(err)
	}

	for name, vhostCert := range certs {
		cert, err := MakeSNIRequest(
			context.Background(),
			loopbackResolver(),
			net.JoinHostPort("scanner-target.example", port),
			name,
			5*time.Second,
			false,
		)
		if err != nil {
			t.Fatalf("SNI %q: unexpected error: %v", name, err)
		}
		if got := srv.seenName(t); got != name {
			t.Fatalf("server observed SNI %q, want %q", got, name)
		}
		if !bytes.Equal(cert.Raw, vhostCert.Certificate[0]) {
			t.Fatalf("SNI %q: served certificate does not belong to the requested vhost (names: %v)", name, cert.DNSNames)
		}
		for other := range certs {
			if other != name && containsName(t, cert, other) {
				t.Fatalf("SNI %q: served certificate must not contain %q (names: %v)", name, other, cert.DNSNames)
			}
		}
	}
}

// TestMakeSNIRequest_OddSNIValuesSentVerbatim pins the probe variants the old
// live tests exercised: port-like names, whitespace, illegal characters and IP
// literals must reach the server unmodified (the hand-rolled encoder bypasses
// the hostname validation that stdlib and uTLS clients enforce).
func TestMakeSNIRequest_OddSNIValuesSentVerbatim(t *testing.T) {
	fallback := makeServerCert(t, "fallback.example")
	srv := newSNIServer(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &fallback, nil
	})

	for _, sni := range []string{"www.example", ":443", " ", "  ", "$", "1.1.0.0"} {
		cert, err := MakeSNIRequest(context.Background(), testResolver(), srv.addr, sni, 5*time.Second, false)
		if err != nil {
			t.Fatalf("SNI %q: unexpected error: %v", sni, err)
		}
		if got := srv.seenName(t); got != sni {
			t.Fatalf("server observed SNI %q, want %q", got, sni)
		}
		if !containsName(t, cert, "fallback.example") {
			t.Fatalf("SNI %q: unexpected certificate names %v", sni, cert.DNSNames)
		}
	}
}

// TestMakeSNIRequest_NoSNIExtension verifies the probe without any server_name
// extension: the server must see no server name and answer with its default
// certificate.
func TestMakeSNIRequest_NoSNIExtension(t *testing.T) {
	fallback := makeServerCert(t, "default.example")
	srv := newSNIServer(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &fallback, nil
	})

	cert, err := MakeSNIRequest(context.Background(), testResolver(), srv.addr, "", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := srv.seenName(t); got != "" {
		t.Fatalf("server observed SNI %q, want none", got)
	}
	if !containsName(t, cert, "default.example") {
		t.Fatalf("unexpected certificate names %v", cert.DNSNames)
	}
}

// TestMakeSNIRequest_EmptySNIExtensionRejected covers the forced zero-length
// host_name entry: the ClientHello is sent, but a conforming server rejects
// it as malformed instead of completing the handshake.
func TestMakeSNIRequest_EmptySNIExtensionRejected(t *testing.T) {
	fallback := makeServerCert(t, "default.example")
	srv := newSNIServer(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &fallback, nil
	})

	_, err := MakeSNIRequest(context.Background(), testResolver(), srv.addr, "", 5*time.Second, true)
	if err == nil {
		t.Fatal("expected a strict server to reject the zero-length SNI entry")
	}
	// The rejection must come from the server (a TLS alert), proving the
	// crafted ClientHello itself was written and sent without error.
	if !strings.Contains(err.Error(), "remote error: tls") {
		t.Fatalf("expected a server-side TLS alert, got %v", err)
	}
}

// TestMakeSNIRequest_UnknownSNIRejected replaces the old TestWrongSNIHostname,
// which sent the correct SNI and only printed the result. A strict vhost that
// only answers for known names must reject an unknown SNI with an
// unrecognized-name alert, classified as ErrTLSUnrecognizedName.
func TestMakeSNIRequest_UnknownSNIRejected(t *testing.T) {
	known := makeServerCert(t, "known.vhost.example")
	srv := newSNIServer(t, func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if chi.ServerName == "known.vhost.example" {
			return &known, nil
		}
		return nil, nil // strict vhost: abort with unrecognized-name alert
	})

	_, err := MakeSNIRequest(context.Background(), testResolver(), srv.addr, "unknown.vhost.example", 5*time.Second, false)
	if err == nil {
		t.Fatal("expected the strict vhost to reject the unknown SNI")
	}
	if !errors.Is(err, ErrTLSUnrecognizedName) {
		t.Fatalf("expected ErrTLSUnrecognizedName, got %v", err)
	}
	if got := srv.seenName(t); got != "unknown.vhost.example" {
		t.Fatalf("server observed SNI %q, want the unknown vhost name", got)
	}

	// Sanity: the same server accepts the SNI it is configured for.
	cert, err := MakeSNIRequest(context.Background(), testResolver(), srv.addr, "known.vhost.example", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error for the known vhost: %v", err)
	}
	if !containsName(t, cert, "known.vhost.example") {
		t.Fatalf("unexpected certificate names %v", cert.DNSNames)
	}
}

// blackholeServer accepts TCP connections but never answers, like a firewalled
// port or a stuck service.
func blackholeServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				time.Sleep(10 * time.Second)
			}()
		}
	}()
	return ln.Addr().String()
}

// TestMakeSNIRequest_Timeout verifies the handshake deadline: a server that
// never answers must produce ErrTimeout, not a TLS classification.
func TestMakeSNIRequest_Timeout(t *testing.T) {
	addr := blackholeServer(t)
	_, err := MakeSNIRequest(context.Background(), testResolver(), addr, "example.com", 300*time.Millisecond, false)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
}

// TestMakeSNIRequest_ContextCancelled verifies that cancelling the scan
// context during the handshake is classified as ErrContextCancelled.
func TestMakeSNIRequest_ContextCancelled(t *testing.T) {
	addr := blackholeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	_, err := MakeSNIRequest(ctx, testResolver(), addr, "example.com", 10*time.Second, false)
	if err == nil {
		t.Fatal("expected a cancellation error")
	}
	if !errors.Is(err, ErrContextCancelled) {
		t.Fatalf("expected ErrContextCancelled, got %v", err)
	}
}

func containsName(t *testing.T, cert *x509.Certificate, name string) bool {
	t.Helper()
	if cert == nil {
		t.Fatal("no certificate returned")
	}
	for _, dnsName := range cert.DNSNames {
		if dnsName == name {
			return true
		}
	}
	return cert.Subject.CommonName == name
}
