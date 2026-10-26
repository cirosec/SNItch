package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/cirosec/snitch/scanner/requests"
)

func TestClassifySNIFailure_ServerAlerts(t *testing.T) {
	ctx := context.Background()
	alerts := []error{
		requests.ErrTLSProtocol,
		requests.ErrTLSUnrecognizedName,
		requests.ErrTLSHandshakeFailure,
		requests.ErrTLSFirstRecord,
		requests.ErrTCPEOF,
		requests.ErrConnectionReset,
		requests.ErrTLSCipherSuite,
		requests.ErrTLSUnexpectedMessage,
		requests.ErrTCPConnectionRefused,
	}
	for _, alert := range alerts {
		if kind := classifySNIFailure(ctx, alert); kind != sniFailureServer {
			t.Fatalf("%v: expected sniFailureServer, got %v", alert, kind)
		}
		// Also through a wrapper, as returned by ErrorHandlerConn.
		wrapped := fmt.Errorf("probe: %w", alert)
		if kind := classifySNIFailure(ctx, wrapped); kind != sniFailureServer {
			t.Fatalf("%v (wrapped): expected sniFailureServer, got %v", alert, kind)
		}
	}
}

func TestClassifySNIFailure_TimeoutIsNotServerBehavior(t *testing.T) {
	_, err := requests.ErrorHandlerConn(errors.New("dial tcp 10.0.0.1:443: i/o timeout"))
	if kind := classifySNIFailure(context.Background(), err); kind != sniFailureTimeout {
		t.Fatalf("expected sniFailureTimeout, got %v", kind)
	}
	if allowsTriState(classifySNIFailure(context.Background(), err)) != TriStateUnknown {
		t.Fatal("a timeout must not record a definitive TriState")
	}
}

func TestClassifySNIFailure_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Cancellation surfaces as a generic closed-connection error once the
	// watchdog closes the conn mid-handshake.
	closed := errors.New("read tcp 10.0.0.1:443->10.0.0.2:1: use of closed network connection")
	if kind := classifySNIFailure(ctx, closed); kind != sniFailureCancelled {
		t.Fatalf("expected sniFailureCancelled, got %v", kind)
	}
	// The classified sentinel must map the same way without ctx inspection.
	if kind := classifySNIFailure(context.Background(), requests.ErrContextCancelled); kind != sniFailureCancelled {
		t.Fatalf("expected sniFailureCancelled, got %v", kind)
	}
}

func TestClassifySNIFailure_UnknownAndNil(t *testing.T) {
	ctx := context.Background()
	if kind := classifySNIFailure(ctx, errors.New("something odd")); kind != sniFailureUnknown {
		t.Fatalf("expected sniFailureUnknown, got %v", kind)
	}
	if kind := classifySNIFailure(ctx, nil); kind != sniFailureUnknown {
		t.Fatalf("nil must not be classified as server behavior, got %v", kind)
	}
}

func TestClassifySNIFailure_URL(t *testing.T) {
	// An unclassified *url.Error from the HTTP client previously recorded a
	// definitive state; it keeps counting as a server-side rejection.
	raw := &url.Error{Op: "Get", URL: "https://10.0.0.1", Err: errors.New("tls: insufficient data")} // deliberately unclassified
	if kind := classifySNIFailure(context.Background(), raw); kind != sniFailureServer {
		t.Fatalf("expected sniFailureServer, got %v", kind)
	}
}

func TestAllowsTriState(t *testing.T) {
	if allowsTriState(sniFailureServer) != TriStateFalse {
		t.Fatal("server rejection must record TriStateFalse for \"allows\" properties")
	}
	for _, kind := range []sniFailureKind{sniFailureTimeout, sniFailureCancelled, sniFailureUnknown} {
		if allowsTriState(kind) != TriStateUnknown {
			t.Fatalf("%v must stay TriStateUnknown", kind)
		}
	}
}