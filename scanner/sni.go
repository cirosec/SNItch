package scanner

import (
	"context"
	"crypto/x509"
	"strings"

	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/helpers"
)

type ScannerRootResult struct {
	Target                     string
	SNIFallbackCertificate     string   // Certificate identified as the fallback certificate the server returns when it doesn't know better
	SNIAllowsMissing           TriState // Whether the server allows connection without SNI
	SNIAllowsEmpty             TriState // Whether a space-only SNI value is allowed
	SNIAllowsEmptyWithExt      TriState // Whether the server allows an empty SNI value with the extension present
	SNIDisconnectsOnRandom     TriState // Whether a randomly generated SNI host is allowed
	SNIAllowsAny               TriState // Server allows all SNI values
	SNIAllowsIPasSNI           TriState // Whether the server allows the target IP as SNI value
	SNIIPCertificate           string   // Certificate returned when using the target IP as SNI
	SNIMultiName               TriState // Whether the server accepts a multi-name ServerNameList
	SNIMultiNameCertificate    string   // Certificate returned for a multi-name ServerNameList
	SNIDuplicateExt            TriState // Whether the server accepts a duplicated server_name extension
	SNIDuplicateExtCertificate string   // Certificate returned for a duplicated server_name extension
	SNIReflectsName            TriState // Whether the server echoes the requested SNI back in the certificate (dynamic/per-SNI issuer)
	HTTPReflectsHost           bool     // Whether the target echoes the requested Host into its redirects (catch-all)
	EmptySNIHttpStatus         int      // HTTP status observed on a no-SNI connection
	EmptySNIHttpTitle          string   // HTTP title observed on a no-SNI connection
	EmptySNIHttpRedirect       string   // HTTP redirect observed on a no-SNI connection
	PlainHTTPHost              string   // Host header variant that produced the (HTTP) result
	PlainHTTPHostRandom        bool     // Whether that variant was the random hostname probe
	PlainHTTPHostNoHost        bool     // Whether that variant was the Host-less HTTP/1.0 probe
	PlainHTTPStatus            int      // HTTP status observed on a plaintext HTTP request to the IP
	PlainHTTPTitle             string   // HTTP title observed on a plaintext HTTP request to the IP
	PlainHTTPRedirect          string   // HTTP redirect observed on a plaintext HTTP request to the IP
	PlainHTTPTLSHost           string   // Host header variant that produced the (HTTP/TLS) result
	PlainHTTPTLSHostRandom     bool     // Whether that variant was the random hostname probe
	PlainHTTPTLSHostNoHost     bool     // Whether that variant was the Host-less HTTP/1.0 probe
	PlainHTTPTLSStatus         int      // HTTP status observed on a plaintext HTTP request to the target's TLS port
	PlainHTTPTLSTitle          string   // HTTP title observed on a plaintext HTTP request to the target's TLS port
	PlainHTTPTLSRedirect       string   // HTTP redirect observed on a plaintext HTTP request to the target's TLS port
	skipIPasSNI                bool     // If true, skip the IP-as-SNI check
	skipPlainHTTP              bool     // If true, skip the plaintext HTTP checks
	httpPort                   string   // Port used for plaintext HTTP requests (default 80)
	executed                   bool     // Indicates whether the scan of this object has already been conducted
	HttpTitle                  string   // HTTP title of the random subdomain site
	HttpStatus                 int      // HTTP Status code of the random subdomain site
	HttpRedirect               string
	gctx                       *globalcontext.GlobalContext
}

func (sTC *ScannerRootResult) AddCertificate(c *x509.Certificate) {
	sTC.gctx.AddCertificate(sTC.Target, c)
}

func (sTC *ScannerRootResult) SetFallbackCertificate(c *x509.Certificate) {
	if c == nil {
		return
	}
	sTC.gctx.RegisterCertificate(c)
	sTC.SNIFallbackCertificate = c.SerialNumber.String()
}

func NewScannerRootResult(target string, globalContext *globalcontext.GlobalContext, skipIPasSNI bool, skipPlainHTTP bool, httpPort string) *ScannerRootResult {
	return &ScannerRootResult{Target: target, executed: false, gctx: globalContext, skipIPasSNI: skipIPasSNI, skipPlainHTTP: skipPlainHTTP, httpPort: httpPort}
}

func (sTC *ScannerRootResult) Run(ctx context.Context) {
	if sTC.executed {
		return
	}
	// Should the system block this test at least the http tests are executed
	sTC.checkHTTP(ctx)
	if ctx.Err() != nil {
		return
	}
	// Plaintext HTTP probing is a separate, IP-only check and runs before the
	// SNI-specific checks so the SNI-strict case (which never reaches the
	// no-SNI HTTP path) still benefits from a Host-header reveal. The target's
	// own (TLS) port is probed as well, since a server may answer plaintext
	// HTTP there and leak a hostname.
	if !sTC.skipPlainHTTP {
		sTC.checkPlainHTTP(ctx)
		if ctx.Err() != nil {
			return
		}
		sTC.checkPlainHTTPTLS(ctx)
		if ctx.Err() != nil {
			return
		}
	}
	sTC.checkNoSNI(ctx)
	if ctx.Err() != nil {
		return
	}
	sTC.checkSNIWithSpaces(ctx)
	if ctx.Err() != nil {
		return
	}
	sTC.checkEmptySNIWithExtension(ctx)
	if ctx.Err() != nil {
		return
	}
	sTC.SNICheckRandom(ctx)
	if ctx.Err() != nil {
		return
	}
	sTC.checkSNIMultiName(ctx)
	if ctx.Err() != nil {
		return
	}
	sTC.checkSNIDuplicateExtension(ctx)
	if ctx.Err() != nil {
		return
	}
	if !sTC.skipIPasSNI {
		sTC.checkSNIWithIP(ctx)
	}
	sTC.executed = true
}

type ScannerSubdomainResult struct {
	Target                 string // Contains the ip:port of the target server
	wildcardDomain         string // Contains the wildcard-FQDN for the target. Example: *.cirosec.de or *.somesubdomain.cirosec.de
	SNIresult              error  // Potential SNI errors
	executed               bool   // tracks if this result element has actually been run. Prevents it from being run multiple times
	SNIFallbackCertificate string // Certificate returned for a random subdomain of the wildcard domain. Eg: the certificate returned for sdkjshr.cirosec.de for wildcard *.cirosec.de
	HTTPReflectsHost       bool   // Whether the target echoed the requested Host into its redirect (catch-all)
	HttpTitle              string // HTTP title of the random subdomain
	HttpStatus             int    // HTTP status of the random subdomain
	HttpRedirect           string
	gctx                   *globalcontext.GlobalContext
}

func NewScannerSubdomainResult(wildcardDomain string, target string, globalContext *globalcontext.GlobalContext) *ScannerSubdomainResult {
	return &ScannerSubdomainResult{executed: false, HttpRedirect: "", Target: target, wildcardDomain: wildcardDomain, gctx: globalContext}
}

func (sWC *ScannerSubdomainResult) AddCertificate(c *x509.Certificate) {
	// Registers a certificate to the global context for indexing
	sWC.SNIFallbackCertificate = c.SerialNumber.String()
	sWC.gctx.AddCertificate(sWC.Target, c)
}

func (sWC *ScannerSubdomainResult) Run(ctx context.Context) {
	if sWC.executed {
		return
	}
	sWC.checkSNI(ctx, sWC.Target)
	if ctx.Err() != nil {
		return
	}
	sWC.checkHTTP(ctx, sWC.Target)
	sWC.executed = true
}

type ScannerHostnameResult struct {
	Target           string
	hostname         string
	Certificate      string
	SNIresult        error
	EncodingVariants map[string]string // Successful alternative SNI encoding -> certificate serial
	executed         bool
	HttpTitle        string
	HttpStatus       int
	HttpRedirect     string
	gctx             *globalcontext.GlobalContext
}

func NewSNIHostnameResult(hostname string, target string, globalContext *globalcontext.GlobalContext) *ScannerHostnameResult {
	return &ScannerHostnameResult{Target: target, hostname: hostname, HttpRedirect: "", HttpTitle: "", HttpStatus: 0, executed: false, gctx: globalContext, Certificate: ""}
}

func (sHC *ScannerHostnameResult) AddCertificate(c *x509.Certificate) {
	sHC.Certificate = c.SerialNumber.String()
	sHC.gctx.AddCertificate(sHC.Target, c)
}

// markMintedCertificate flags the certificate served for a requested name as
// reflected when the target is known to issue a fresh certificate per SNI
// (a dynamic issuer). Such certificates merely echo the requested name (or an
// encoding variant of it); their names are not discoveries and must not be fed
// back into recon, where they would be probed against every other target. A
// certificate that does not contain the requested name is treated as the
// target's real (static) certificate and keeps its names usable.
func (sHC *ScannerHostnameResult) markMintedCertificate(target string, certificate *x509.Certificate, requested string) {
	if certificate == nil {
		return
	}
	if sHC.gctx.TargetIssuesRandomCerts(target) && reflectsSNI(certificate, requested) {
		sHC.gctx.MarkReflectedCertificate(certificate.SerialNumber.String())
	}
}

// reflectsSNI reports whether a leaf certificate returned for the requested
// SNI value echoes that value in its CommonName or SANs. A server that mints a
// unique certificate per SNI (e.g. a TLS proxy or an appliance generating
// certificates on the fly) reflects the requested name, which makes every
// "discovered" hostname a mere reflection rather than a real vhost.
func reflectsSNI(certificate *x509.Certificate, requested string) bool {
	if certificate == nil || requested == "" {
		return false
	}
	if strings.EqualFold(certificate.Subject.CommonName, requested) {
		return true
	}
	return helpers.ContainsFold(certificate.DNSNames, requested)
}

func (sHC *ScannerHostnameResult) Run(ctx context.Context) {
	if sHC.executed {
		return
	}
	sHC.checkSNI(ctx, sHC.Target)
	if ctx.Err() != nil {
		return
	}
	sHC.checkSNIVariants(ctx, sHC.Target)
	if ctx.Err() != nil {
		return
	}
	sHC.checkHTTP(ctx, sHC.Target)
	sHC.executed = true
}
