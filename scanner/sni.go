package scanner

import (
	"context"
	"crypto/x509"
	"github.com/cirosec/snitch/globalcontext"
)

type ScannerRootResult struct {
	Target                 string
	SNIFallbackCertificate string   // Certificate identified as the fallback certificate the server returns when it doesn't know better
	SNIAllowsMissing       TriState // Whether the server allows connection without SNI
	SNIAllowsEmpty         TriState // Whether a space-only SNI value is allowed
	SNIAllowsEmptyWithExt  TriState // Whether the server allows an empty SNI value with the extension present
	SNIDisconnectsOnRandom TriState // Whether a randomly generated SNI host is allowed
	SNIAllowsAny           TriState // Server allows all SNI values
	SNIAllowsIPasSNI       TriState // Whether the server allows the target IP as SNI value
	SNIIPCertificate       string   // Certificate returned when using the target IP as SNI
	skipIPasSNI            bool     // If true, skip the IP-as-SNI check
	executed               bool     // Indicates whether the scan of this object has already been conducted
	HttpTitle              string   // HTTP title of the random subdomain site
	HttpStatus             int      // HTTP Status code of the random subdomain site
	HttpRedirect           string
	gctx                   *globalcontext.GlobalContext
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

func NewScannerRootResult(target string, globalContext *globalcontext.GlobalContext, skipIPasSNI bool) *ScannerRootResult {
	return &ScannerRootResult{Target: target, executed: false, gctx: globalContext, skipIPasSNI: skipIPasSNI}
}

func (sTC *ScannerRootResult) Run(ctx context.Context) {
	if sTC.executed {
		return
	}
	// Should the system block this test at least the http tests are executed
	sTC.checkHTTP()
	if ctx.Err() != nil {
		return
	}
	sTC.checkNoSNI()
	if ctx.Err() != nil {
		return
	}
	sTC.checkSNIWithSpaces()
	if ctx.Err() != nil {
		return
	}
	sTC.checkEmptySNIWithExtension()
	if ctx.Err() != nil {
		return
	}
	sTC.SNICheckRandom()
	if ctx.Err() != nil {
		return
	}
	if !sTC.skipIPasSNI {
		sTC.checkSNIWithIP()
	}
	sTC.executed = true
}

type ScannerSubdomainResult struct {
	Target                 string // Contains the ip:port of the target server
	wildcardDomain         string // Contains the wildcard-FQDN for the target. Example: *.cirosec.de or *.somesubdomain.cirosec.de
	SNIresult              error  // Potential SNI errors
	executed               bool   // tracks if this result element has actually been run. Prevents it from being run multiple times
	SNIFallbackCertificate string // Certificate returned for a random subdomain of the wildcard domain. Eg: the certificate returned for sdkjshr.cirosec.de for wildcard *.cirosec.de
	HttpTitle              string // HTTP title of the random subdomain
	HttpStatus             int    // HTTP Status code of the random subdomain
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
	sWC.checkSNI(sWC.Target)
	if ctx.Err() != nil {
		return
	}
	sWC.checkHTTP(sWC.Target)
	sWC.executed = true
}

type ScannerHostnameResult struct {
	Target       string
	hostname     string
	Certificate  string
	SNIresult    error
	executed     bool
	HttpTitle    string
	HttpStatus   int
	HttpRedirect string
	gctx         *globalcontext.GlobalContext
}

func NewSNIHostnameResult(hostname string, target string, globalContext *globalcontext.GlobalContext) *ScannerHostnameResult {
	return &ScannerHostnameResult{Target: target, hostname: hostname, HttpRedirect: "", HttpTitle: "", HttpStatus: 0, executed: false, gctx: globalContext, Certificate: ""}
}

func (sHC *ScannerHostnameResult) AddCertificate(c *x509.Certificate) {
	sHC.Certificate = c.SerialNumber.String()
	sHC.gctx.AddCertificate(sHC.Target, c)
}

func (sHC *ScannerHostnameResult) Run(ctx context.Context) {
	if sHC.executed {
		return
	}
	sHC.checkSNI(sHC.Target)
	if ctx.Err() != nil {
		return
	}
	sHC.checkHTTP(sHC.Target)
	sHC.executed = true
}
