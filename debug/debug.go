package debug

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
)

// DebugLogger writes structured debug output to a file.
// All methods are nil-receiver safe — callers never need guards.
type DebugLogger struct {
	logger *log.Logger
	file   *os.File
}

// NewDebugLogger creates a DebugLogger that writes to the given file path.
func NewDebugLogger(filename string) (*DebugLogger, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create debug log file: %w", err)
	}
	l := log.New(f, "", log.LstdFlags)
	return &DebugLogger{logger: l, file: f}, nil
}

// NopLogger returns nil, which is a valid no-op DebugLogger.
func NopLogger() *DebugLogger {
	return nil
}

// Close flushes and closes the debug log file.
func (d *DebugLogger) Close() {
	if d == nil {
		return
	}
	d.file.Close()
}

// Logf writes a general-purpose debug line.
func (d *DebugLogger) Logf(format string, args ...interface{}) {
	if d == nil {
		return
	}
	d.logger.Printf(format, args...)
}

// ScanConfig logs the scan configuration.
func (d *DebugLogger) ScanConfig(targets, hosts []string, threads, epochs int, recon, crtlog, ptr bool) {
	if d == nil {
		return
	}
	d.logger.Printf("[CONFIG] Targets=[%s] Hosts=[%s]", strings.Join(targets, ", "), strings.Join(hosts, ", "))
	d.logger.Printf("[CONFIG] Threads=%d Epochs=%d Recon=%t CRTLOG=%t PTR=%t", threads, epochs, recon, crtlog, ptr)
}

// TargetOnline logs that a target is reachable.
func (d *DebugLogger) TargetOnline(target string) {
	if d == nil {
		return
	}
	d.logger.Printf("[TARGET] %s online", target)
}

// TargetOffline logs that a target is unreachable.
func (d *DebugLogger) TargetOffline(target string) {
	if d == nil {
		return
	}
	d.logger.Printf("[TARGET] %s offline", target)
}

// SNIRequest logs an SNI TLS handshake request and its result.
func (d *DebugLogger) SNIRequest(target, sni string, cert *x509.Certificate, err error) {
	if d == nil {
		return
	}
	if err != nil {
		d.logger.Printf("[SNI] %s SNI=%q → error: %s", target, sni, err.Error())
		return
	}
	if cert == nil {
		d.logger.Printf("[SNI] %s SNI=%q → no certificate", target, sni)
		return
	}
	serial := cert.SerialNumber.String()
	if len(serial) > 10 {
		serial = serial[:10]
	}
	sans := make([]string, len(cert.DNSNames)+1)
	copy(sans, cert.DNSNames)
	sans[len(cert.DNSNames)] = cert.Subject.CommonName
	d.logger.Printf("[SNI] %s SNI=%q → cert serial=%s SANs=%v", target, sni, serial, sans)
}

// HTTPRequest logs an HTTP request and its result.
func (d *DebugLogger) HTTPRequest(target, host string, status int, title, redirect string, err error) {
	if d == nil {
		return
	}
	if err != nil {
		d.logger.Printf("[HTTP] %s Host=%q → error: %s", target, host, err.Error())
		return
	}
	d.logger.Printf("[HTTP] %s Host=%q → %d title=%q redirect=%q", target, host, status, title, redirect)
}

// PlainHTTPRequest logs a plaintext HTTP request to a target IP and its result.
func (d *DebugLogger) PlainHTTPRequest(target, host, port string, status int, title, redirect string, err error) {
	if d == nil {
		return
	}
	if err != nil {
		d.logger.Printf("[HTTP-PLAIN] %s (port %s) Host=%q → error: %s", target, port, host, err.Error())
		return
	}
	d.logger.Printf("[HTTP-PLAIN] %s (port %s) Host=%q → %d title=%q redirect=%q", target, port, host, status, title, redirect)
}

// PTRResult logs reverse DNS (PTR) lookup results for a single IP.
func (d *DebugLogger) PTRResult(ip string, hostnames []string) {
	if d == nil {
		return
	}
	d.logger.Printf("[PTR] %s → %v", ip, hostnames)
}

// CrtLogResult logs crt.name query results for a domain.
func (d *DebugLogger) CrtLogResult(domain string, hostnames []string, err error) {
	if d == nil {
		return
	}
	if err != nil {
		d.logger.Printf("[CRTLOG] %s → error: %s", domain, err.Error())
		return
	}
	d.logger.Printf("[CRTLOG] %s → %d hostnames: %v", domain, len(hostnames), hostnames)
}

// CertRecon logs hostnames discovered from a certificate during recon.
func (d *DebugLogger) CertRecon(certSerial string, targets, hostnames []string) {
	if d == nil {
		return
	}
	if len(certSerial) > 10 {
		certSerial = certSerial[:10]
	}
	d.logger.Printf("[CERT-RECON] cert=%s targets=[%s] → discovered %v", certSerial, strings.Join(targets, ", "), hostnames)
}

// RedirectRecon logs hostnames discovered from HTTP redirects.
func (d *DebugLogger) RedirectRecon(hostnames []string) {
	if d == nil {
		return
	}
	d.logger.Printf("[REDIRECT] discovered: %v", hostnames)
}

// HeaderRecon logs hostnames discovered from HTTP response headers.
func (d *DebugLogger) HeaderRecon(hostnames []string) {
	if d == nil {
		return
	}
	d.logger.Printf("[HEADERS] discovered: %v", hostnames)
}

// HostAdded logs when a new host is added to the scan queue.
func (d *DebugLogger) HostAdded(source, hostname string) {
	if d == nil {
		return
	}
	d.logger.Printf("[HOST-ADDED] source=%s hostname=%s", source, hostname)
}

// Iteration logs the start of a scan iteration.
func (d *DebugLogger) Iteration(number, maxEpochs, unscannedCount int) {
	if d == nil {
		return
	}
	d.logger.Printf("[ITER] Iteration %d/%d — %d unscanned hosts", number, maxEpochs, unscannedCount)
}
