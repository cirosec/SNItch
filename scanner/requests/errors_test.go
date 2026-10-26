package requests

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"testing"
)

func TestErrorHandlerConn_Nil(t *testing.T) {
	match, err := ErrorHandlerConn(nil)
	if match || err != nil {
		t.Fatalf("expected (false, nil) for nil input, got (%v, %v)", match, err)
	}
}

func TestErrorHandlerConn_Timeout(t *testing.T) {
	raw := errors.New("dial tcp 10.0.0.1:443: i/o timeout")
	match, err := ErrorHandlerConn(raw)
	if !match || !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, match=%v err=%v", match, err)
	}
	if errors.Is(err, ErrTLSProtocol) {
		t.Fatalf("i/o timeout must not be classified as ErrTLSProtocol: %v", err)
	}
}

func TestErrorHandlerConn_ConnectionTimedOut(t *testing.T) {
	raw := errors.New("dial tcp 10.0.0.1:443: connect: connection timed out")
	match, err := ErrorHandlerConn(raw)
	if !match || !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, match=%v err=%v", match, err)
	}
}

func TestErrorHandlerConn_DeadlineExceeded(t *testing.T) {
	raw := &url.Error{Op: "Get", URL: "https://10.0.0.1", Err: context.DeadlineExceeded}
	match, err := ErrorHandlerConn(raw)
	if !match || !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, match=%v err=%v", match, err)
	}
}

func TestErrorHandlerConn_ContextCancelled(t *testing.T) {
	raw := errors.New(`Get "https://10.0.0.1": context canceled`)
	match, err := ErrorHandlerConn(raw)
	if !match || !errors.Is(err, ErrContextCancelled) {
		t.Fatalf("expected ErrContextCancelled, match=%v err=%v", match, err)
	}
	match, err = ErrorHandlerConn(context.Canceled)
	if !match || !errors.Is(err, ErrContextCancelled) {
		t.Fatalf("expected ErrContextCancelled for context.Canceled, match=%v err=%v", match, err)
	}
}

func TestErrorHandlerConn_WrappingPreservesOriginal(t *testing.T) {
	raw := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	match, err := ErrorHandlerConn(raw)
	if !match || !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, match=%v err=%v", match, err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatalf("wrapped error must preserve the original for errors.As: %v", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("wrapped error must preserve the original *net.OpError: %v", err)
	}
}

func TestErrorHandlerConn_ExistingMappings(t *testing.T) {
	cases := []struct {
		raw      string
		sentinel error
	}{
		{"remote error: tls: internal error", ErrTLSProtocol},
		{"remote error: tls: TLS protocol error", ErrTLSProtocol},
		{"read: connection reset by peer", ErrConnectionReset},
		{"remote error: tls: unrecognized name", ErrTLSUnrecognizedName},
		{"EOF", ErrTCPEOF},
		{"read tcp: end of file", ErrTCPEOF},
		{"remote error: tls: handshake failure", ErrTLSHandshakeFailure},
		{"remote error: tls: handshake Failure", ErrTLSHandshakeFailure}, // case-insensitive duplicate
		{"tls: first record does not look like a TLS handshake", ErrTLSFirstRecord},
		{`Get "https://10.0.0.1": server gave HTTP response to HTTPS client`, ErrTLSFirstRecord},
		{"tls: server chose an unconfigured cipher suite", ErrTLSCipherSuite},
		{"remote error: tls: unexpected message", ErrTLSUnexpectedMessage},
		{"dial tcp 10.0.0.1:443: connect: connection refused", ErrTCPConnectionRefused},
	}
	for _, c := range cases {
		match, err := ErrorHandlerConn(errors.New(c.raw))
		if !match || !errors.Is(err, c.sentinel) {
			t.Fatalf("%q: expected %v, match=%v err=%v", c.raw, c.sentinel, match, err)
		}
	}
}

func TestErrorHandlerConn_UnclassifiedUnchanged(t *testing.T) {
	raw := errors.New("use of closed network connection")
	match, err := ErrorHandlerConn(raw)
	if match || !errors.Is(err, raw) {
		t.Fatalf("unclassified error must be returned unchanged, match=%v err=%v", match, err)
	}
}

// Real net timeouts produced by the dialer/handshake deadline must classify as
// timeouts even when wrapped by url.Error, as the HTTP client returns them.
func TestErrorHandlerConn_ClassifiedThroughURL(t *testing.T) {
	raw := &url.Error{Op: "Get", URL: "https://10.0.0.1", Err: &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}}
	match, err := ErrorHandlerConn(raw)
	if !match || !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, match=%v err=%v", match, err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatalf("wrapped error must preserve the original for errors.As: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("wrapped error must preserve the original timeout sentinel: %v", err)
	}
}