package requests

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var ErrTLSProtocol = errors.New("TLS protocol error")
var ErrConnectionReset = errors.New("TCP connection reset")
var ErrTLSUnrecognizedName = errors.New("TLS unrecognized name")
var ErrTCPEOF = errors.New("end of file")
var ErrTLSHandshakeFailure = errors.New("handshake failure")
var ErrTLSFirstRecord = errors.New("first record does not look like a TLS handshake")
var ErrTLSUnexpectedMessage = errors.New("unexpected TLS Message")
var ErrTLSCipherSuite = errors.New("TLS unconfigured cipher suite")
var ErrTCPConnectionRefused = errors.New("TCP connection refused")
var ErrTimeout = errors.New("network timeout")
var ErrContextCancelled = errors.New("scan context cancelled")

// wrapClassified keeps the original error inspectable (errors.Is/As) while
// tagging it with the classified sentinel.
func wrapClassified(sentinel, err error) error {
	return fmt.Errorf("%w: %w", sentinel, err)
}

func ErrorHandlerConn(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context canceled") || errors.Is(err, context.Canceled):
		return true, wrapClassified(ErrContextCancelled, err)
	case strings.Contains(msg, "remote error: tls: internal error"):
		//Occurs when the HTTP server returns an error in the TLS protocol
		return true, wrapClassified(ErrTLSProtocol, err)
	case strings.Contains(msg, "tls protocol error"):
		return true, wrapClassified(ErrTLSProtocol, err)
	case strings.Contains(msg, "connection reset by peer") || strings.Contains(msg, "tcp connection reset"):
		//Occurs when a MitM kills the connection. This is an indicator for a firewall like FortiGate
		return true, wrapClassified(ErrConnectionReset, err)
	case strings.Contains(msg, " unrecognized name"):
		//TLS built-in error that tells the client that an unknown SNI was sent
		return true, wrapClassified(ErrTLSUnrecognizedName, err)
	case strings.Contains(msg, "eof") || strings.Contains(msg, "end of file"):
		return true, wrapClassified(ErrTCPEOF, err)
	case strings.Contains(msg, "handshake failure"):
		return true, wrapClassified(ErrTLSHandshakeFailure, err)
	case strings.Contains(msg, "first record does not look like a tls handshake"):
		return true, wrapClassified(ErrTLSFirstRecord, err)
	case strings.Contains(msg, "server gave http response to https client"):
		// net/http reports this when a plaintext HTTP response is received
		// where a TLS handshake was expected - i.e. an HTTP service answering
		// on the HTTPS port. Same root cause as the crypto/tls first-record
		// error, just reported differently by the HTTP transport.
		return true, wrapClassified(ErrTLSFirstRecord, err)
	case strings.Contains(msg, "server chose an unconfigured cipher suite"):
		//Occurs when the server selects a cipher suite the client did not offer
		return true, wrapClassified(ErrTLSCipherSuite, err)
	case strings.Contains(msg, "unexpected message"):
		return true, wrapClassified(ErrTLSUnexpectedMessage, err)
	case strings.Contains(msg, "connection refused"):
		return true, wrapClassified(ErrTCPConnectionRefused, err)
	case strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "connection timed out") ||
		strings.Contains(msg, "context deadline exceeded") || errors.Is(err, context.DeadlineExceeded):
		// A timeout says nothing about server behavior; it is not a TLS error.
		return true, wrapClassified(ErrTimeout, err)
	}
	return false, err
}