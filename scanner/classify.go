package scanner

import (
	"context"
	"errors"
	"net/url"

	"github.com/cirosec/snitch/scanner/requests"
)

// sniFailureKind categorizes why an SNI probe failed.
type sniFailureKind int

const (
	// The server actively rejected the handshake (TLS alert, reset, EOF).
	sniFailureServer sniFailureKind = iota
	// The probe timed out; no statement about server behavior is possible.
	sniFailureTimeout
	// The scan was cancelled mid-probe.
	sniFailureCancelled
	// The error could not be classified.
	sniFailureUnknown
)

// classifySNIFailure maps a probe error onto a failure category. Network
// conditions (timeouts, cancellation) and unclassified errors are deliberately
// kept apart from server-side TLS behavior so that only the latter is ever
// recorded as a measured property of the server.
func classifySNIFailure(ctx context.Context, err error) sniFailureKind {
	if ctx.Err() != nil {
		// The scan was cancelled and closing the connection surfaced as a
		// generic "use of closed network connection" error. Not a finding.
		return sniFailureCancelled
	}
	if err == nil {
		return sniFailureUnknown
	}
	if errors.Is(err, requests.ErrContextCancelled) {
		return sniFailureCancelled
	}
	if errors.Is(err, requests.ErrTimeout) {
		return sniFailureTimeout
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return sniFailureServer
	}
	switch {
	case errors.Is(err, requests.ErrTLSProtocol),
		errors.Is(err, requests.ErrTLSUnrecognizedName),
		errors.Is(err, requests.ErrTLSHandshakeFailure),
		errors.Is(err, requests.ErrTLSFirstRecord),
		errors.Is(err, requests.ErrTCPEOF),
		errors.Is(err, requests.ErrConnectionReset),
		errors.Is(err, requests.ErrTLSCipherSuite),
		errors.Is(err, requests.ErrTLSUnexpectedMessage),
		errors.Is(err, requests.ErrTCPConnectionRefused):
		return sniFailureServer
	}
	return sniFailureUnknown
}

// allowsTriState maps a classified probe failure onto the TriState of a
// "server allows X" property. Only a definitive server-side rejection
// records False; timeouts, cancellation and unknown errors stay Unknown.
func allowsTriState(kind sniFailureKind) TriState {
	if kind == sniFailureServer {
		return TriStateFalse
	}
	return TriStateUnknown
}