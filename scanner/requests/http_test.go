package requests

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// plaintextServer starts a TCP listener that answers whatever it receives with
// a plaintext HTTP response, mimicking an HTTP service exposed on the HTTPS
// port. It returns the listener address.
func plaintextServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}()
		}
	}()
	return ln.Addr().String()
}

// A crafted TLS ClientHello sent to a plaintext server (an HTTP service on the
// HTTPS port) must be classified as ErrTLSFirstRecord.
func TestMakeSNIRequest_PlaintextServer(t *testing.T) {
	addr := plaintextServer(t)
	_, err := MakeSNIRequest(context.Background(), testResolver(), addr, "example.com", 5*time.Second, false)
	if err == nil {
		t.Fatal("expected an error when sending a TLS handshake to a plaintext server")
	}
	if !errors.Is(err, ErrTLSFirstRecord) {
		t.Fatalf("expected ErrTLSFirstRecord, got %v", err)
	}
}

// An HTTPS request to a plaintext server is reported by net/http as "server
// gave HTTP response to HTTPS client" and must map to ErrTLSFirstRecord.
func TestMakeHTTPRequest_PlaintextServer(t *testing.T) {
	addr := plaintextServer(t)
	_, _, err := MakeHTTPRequest(context.Background(), testResolver(), addr, "example.com", 5*time.Second, "")
	if err == nil {
		t.Fatal("expected an error when sending an HTTPS request to a plaintext server")
	}
	if !errors.Is(err, ErrTLSFirstRecord) {
		t.Fatalf("expected ErrTLSFirstRecord, got %v", err)
	}
}

// TestErrorHandlerConn_FirstRecord pins the error-string mapping for the
// "plaintext on the TLS port" case.
func TestErrorHandlerConn_FirstRecord(t *testing.T) {
	raw := errors.New(`Get "https://127.0.0.1:443": tls: first record does not look like a TLS handshake`)
	match, err := ErrorHandlerConn(raw)
	if !match || !errors.Is(err, ErrTLSFirstRecord) {
		t.Fatalf("expected ErrTLSFirstRecord, match=%v err=%v", match, err)
	}
}

// TestReadBody_BodyCap pins the 1 MiB cap: a hostile oversized response must
// be truncated instead of being fully buffered.
func TestReadBody_BodyCap(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 2*maxBodySize)))}
	if got := len(ReadBody(resp)); got != maxBodySize {
		t.Fatalf("expected body capped at %d bytes, got %d", maxBodySize, got)
	}
}
