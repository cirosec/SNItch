package requests

import (
	"errors"
	"strings"
)

var ErrTLSProtocol = errors.New("TLS protocol error")
var ErrConnectionReset = errors.New("TCP connection reset")
var ErrTLSUnrecognizedName = errors.New("TLS unrecognized name")
var ErrTCPEOF = errors.New("end of file")
var ErrTLSHandshakeFailure = errors.New("handshake failure")
var ErrTLSFirstRecord = errors.New("first record does not look like a TLS handshake")
var ErrTLSUnexpectedMessage = errors.New("unexpected TLS Message")
var ErrTCPConnectionRefused = errors.New("TCP connection refused")

func ErrorHandlerConn(err error) (bool, error) {
	if strings.Contains(err.Error(), "remote error: tls: internal error") {
		//Occurs when the HTTP server returns an error in the TLS protocol
		return true, ErrTLSProtocol
	} else if strings.Contains(err.Error(), "TLS protocol error") {
		return true, ErrTLSProtocol
	} else if strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "TCP connection reset") {
		//Occurs when a MitM kills the connection. This is an indicator for a firewall like FortiGate
		return true, ErrConnectionReset
	} else if strings.Contains(strings.ToLower(err.Error()), " unrecognized name") {
		//TLS built-in error that tells the client that an unknown SNI was sent
		return true, ErrTLSUnrecognizedName
	} else if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "end of file") {
		return true, ErrTCPEOF
	} else if strings.Contains(err.Error(), "handshake failure") {
		return true, ErrTLSHandshakeFailure
	} else if strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
		return true, ErrTLSFirstRecord
	} else if strings.Contains(err.Error(), "unexpected message") {
		return true, ErrTLSUnexpectedMessage
	} else if strings.Contains(err.Error(), "connection refused") {
		return true, ErrTCPConnectionRefused
	} else if strings.Contains(err.Error(), "handshake Failure") {
		return true, ErrTLSHandshakeFailure
	} else if strings.Contains(err.Error(), "i/o timeout") {
		return true, ErrTLSProtocol
	}
	return false, err
}
