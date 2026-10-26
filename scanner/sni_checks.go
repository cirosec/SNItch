package scanner

import (
	"context"

	"net"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/scanner/requests"
)

// check for random SNIs and compare results
func (sTC *ScannerRootResult) SNICheckRandom(ctx context.Context) {
	random1 := helpers.RandStringBytes(10) + ".com"
	certificate, err1 := requests.MakeSNIRequest(
		ctx,
		sTC.gctx.DNSresolver,
		sTC.Target,
		random1, // SNI
		sTC.gctx.Timeout,
		false,
	)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, random1, certificate, err1)
	if err1 != nil && classifySNIFailure(ctx, err1) == sniFailureTimeout {
		// A single timeout is no evidence of a disconnect; retry once.
		certificate, err1 = requests.MakeSNIRequest(
			ctx,
			sTC.gctx.DNSresolver,
			sTC.Target,
			random1, // SNI
			sTC.gctx.Timeout,
			false,
		)
		sTC.gctx.DebugLog.SNIRequest(sTC.Target, random1, certificate, err1)
	}
	if err1 != nil {
		switch classifySNIFailure(ctx, err1) {
		case sniFailureServer:
			sTC.SNIDisconnectsOnRandom = TriStateTrue
		case sniFailureCancelled, sniFailureTimeout:
			// Not a measured server property; leave TriStateUnknown.
		default:
			log.Printf("[%s] Received unknown error in SNICheckRandom for sni '%s': %s", sTC.Target, random1, err1.Error())
		}
		return
	}
	sTC.SNIDisconnectsOnRandom = TriStateFalse
	sTC.AddCertificate(certificate)
	sTC.SetFallbackCertificate(certificate)
	// A cert that echoes the random SNI back is per-SNI/dynamically issued.
	if reflectsSNI(certificate, random1) {
		sTC.SNIReflectsName = TriStateTrue
		sTC.gctx.MarkReflectedCertificate(certificate.SerialNumber.String())
		sTC.gctx.MarkDynamicTarget(sTC.Target)
	}
}

// checkSNIMultiName sends a ServerNameList with two unknown names
func (sTC *ScannerRootResult) checkSNIMultiName(ctx context.Context) {
	randomA := helpers.RandStringBytes(10) + ".com"
	randomB := helpers.RandStringBytes(10) + ".com"
	certificate, err := requests.MakeSNIRequestOpts(
		ctx,
		sTC.gctx.DNSresolver,
		sTC.Target,
		requests.SNIRequestOptions{Names: []string{randomA, randomB}},
		sTC.gctx.Timeout,
	)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, randomA+","+randomB, certificate, err)
	if err != nil {
		if allowsTriState(classifySNIFailure(ctx, err)) == TriStateFalse {
			sTC.SNIMultiName = TriStateFalse
		}
		return
	}
	sTC.SNIMultiName = TriStateTrue
	if certificate != nil {
		sTC.gctx.RegisterCertificate(certificate)
		sTC.SNIMultiNameCertificate = certificate.SerialNumber.String()
		sTC.AddCertificate(certificate)
		if reflectsSNI(certificate, randomA) || reflectsSNI(certificate, randomB) {
			sTC.SNIReflectsName = TriStateTrue
			sTC.gctx.MarkReflectedCertificate(certificate.SerialNumber.String())
			sTC.gctx.MarkDynamicTarget(sTC.Target)
		}
	}
}

// checkSNIDuplicateExtension duplicates the server_name extension in one ClientHello
func (sTC *ScannerRootResult) checkSNIDuplicateExtension(ctx context.Context) {
	random := helpers.RandStringBytes(10) + ".com"
	certificate, err := requests.MakeSNIRequestOpts(
		ctx,
		sTC.gctx.DNSresolver,
		sTC.Target,
		requests.SNIRequestOptions{Names: []string{random}, DuplicateExtension: true},
		sTC.gctx.Timeout,
	)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, random, certificate, err)
	if err != nil {
		if allowsTriState(classifySNIFailure(ctx, err)) == TriStateFalse {
			sTC.SNIDuplicateExt = TriStateFalse
		}
		return
	}
	sTC.SNIDuplicateExt = TriStateTrue
	if certificate != nil {
		sTC.gctx.RegisterCertificate(certificate)
		sTC.SNIDuplicateExtCertificate = certificate.SerialNumber.String()
		sTC.AddCertificate(certificate)
		if reflectsSNI(certificate, random) {
			sTC.SNIReflectsName = TriStateTrue
			sTC.gctx.MarkReflectedCertificate(certificate.SerialNumber.String())
			sTC.gctx.MarkDynamicTarget(sTC.Target)
		}
	}
}

// checks for empty or missing SNI fields
func (sTC *ScannerRootResult) checkNoSNI(ctx context.Context) {
	certificate, err := requests.MakeSNIRequest(
		ctx,
		sTC.gctx.DNSresolver,
		sTC.Target,
		"", // empty string => don't send SNI Extension
		sTC.gctx.Timeout,
		false,
	)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, "", certificate, err)
	if err == nil {
		sTC.SNIAllowsMissing = TriStateTrue
		sTC.AddCertificate(certificate)
	} else if allowsTriState(classifySNIFailure(ctx, err)) == TriStateFalse {
		sTC.SNIAllowsMissing = TriStateFalse
	}

	// Capture the HTTP behavior of the no-SNI connection so the "(EMPTY SNI)"
	// row reflects what a real empty-SNI client (e.g. curl https://<ip>) sees,
	// instead of reusing the random-SNI HTTP result. Only worth probing when
	// the server actually accepted the no-SNI handshake.
	if sTC.SNIAllowsMissing != TriStateTrue {
		return
	}
	status, resp, httpErr := requests.MakeNoSNIHTTPRequest(
		ctx,
		sTC.gctx.DNSresolver,
		sTC.Target,
		sTC.gctx.Timeout,
		sTC.gctx.UserAgent,
	)
	if httpErr == nil && resp != nil {
		sTC.EmptySNIHttpStatus = status
		sTC.EmptySNIHttpTitle = requests.ExtractHTMLTitle(resp)
		sTC.EmptySNIHttpRedirect = resp.Header.Get("Location")
		sTC.gctx.DebugLog.HTTPRequest(sTC.Target, "", status, sTC.EmptySNIHttpTitle, sTC.EmptySNIHttpRedirect, nil)
	} else {
		sTC.gctx.DebugLog.HTTPRequest(sTC.Target, "", -1, "", "", httpErr)
	}
}

// checkEmptySNIWithExtension sends the SNI extension with an empty server name value
func (sTC *ScannerRootResult) checkEmptySNIWithExtension(ctx context.Context) {
	certificate, err := requests.MakeSNIRequest(
		ctx,
		sTC.gctx.DNSresolver,
		sTC.Target,
		"", // empty string SNI value
		sTC.gctx.Timeout,
		true, // force the SNI extension to be included
	)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, "", certificate, err)
	if err == nil {
		sTC.SNIAllowsEmptyWithExt = TriStateTrue
		sTC.AddCertificate(certificate)
	} else if allowsTriState(classifySNIFailure(ctx, err)) == TriStateFalse {
		sTC.SNIAllowsEmptyWithExt = TriStateFalse
	}
}

func (sTC *ScannerRootResult) checkSNIWithSpaces(ctx context.Context) {
	certificate, err := requests.MakeSNIRequest(
		ctx,
		sTC.gctx.DNSresolver,
		sTC.Target,
		"  ",
		sTC.gctx.Timeout,
		false,
	)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, "  ", certificate, err)
	if err == nil {
		sTC.SNIAllowsEmpty = TriStateTrue
		sTC.AddCertificate(certificate)
	} else if allowsTriState(classifySNIFailure(ctx, err)) == TriStateFalse {
		sTC.SNIAllowsEmpty = TriStateFalse
	}
}

func (sHC *ScannerHostnameResult) checkSNI(ctx context.Context, target string) {
	certificate, err := requests.MakeSNIRequest(
		ctx,
		sHC.gctx.DNSresolver,
		target,
		sHC.hostname,
		sHC.gctx.Timeout,
		false,
	)
	sHC.gctx.DebugLog.SNIRequest(target, sHC.hostname, certificate, err)
	sHC.SNIresult = err
	if certificate != nil && err == nil {
		sHC.AddCertificate(certificate)
		sHC.markMintedCertificate(target, certificate, sHC.hostname)
	}
}

// checkSNIVariants probes alternative encodings of the hostname without
// overwriting the literal probe's Certificate/SNIresult.
func (sHC *ScannerHostnameResult) checkSNIVariants(ctx context.Context, target string) {
	for _, variant := range helpers.EncodingVariants(sHC.hostname) {
		certificate, err := requests.MakeSNIRequestOpts(
			ctx,
			sHC.gctx.DNSresolver,
			target,
			requests.SNIRequestOptions{Names: []string{variant}},
			sHC.gctx.Timeout,
		)
		sHC.gctx.DebugLog.SNIRequest(target, variant, certificate, err)
		if certificate == nil || err != nil {
			continue
		}
		sHC.gctx.AddCertificate(target, certificate)
		sHC.markMintedCertificate(target, certificate, variant)
		if sHC.EncodingVariants == nil {
			sHC.EncodingVariants = map[string]string{}
		}
		sHC.EncodingVariants[variant] = certificate.SerialNumber.String()
	}
}

func (sWC *ScannerSubdomainResult) checkSNI(ctx context.Context, target string) {
	domain := strings.TrimPrefix(sWC.wildcardDomain, "*.")
	sni := helpers.RandStringBytes(4) + "." + domain
	certificate, err := requests.MakeSNIRequest(
		ctx,
		sWC.gctx.DNSresolver,
		target,
		sni,
		sWC.gctx.Timeout,
		false,
	)
	sWC.gctx.DebugLog.SNIRequest(target, sni, certificate, err)
	sWC.SNIresult = err
	if certificate != nil && err == nil {
		sWC.AddCertificate(certificate)
		// The wildcard probe uses a random label; if the server echoes it back
		// the certificate is dynamically issued and its "name" is not real.
		if reflectsSNI(certificate, sni) {
			sWC.gctx.MarkReflectedCertificate(certificate.SerialNumber.String())
			sWC.gctx.MarkDynamicTarget(target)
		}
	}
}

// checkSNIWithIP sends the target's IP address as the SNI value
func (sTC *ScannerRootResult) checkSNIWithIP(ctx context.Context) {
	ip, _, err := net.SplitHostPort(sTC.Target)
	if err != nil {
		return
	}
	certificate, sniErr := requests.MakeSNIRequest(ctx, sTC.gctx.DNSresolver, sTC.Target, ip, sTC.gctx.Timeout, true)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, ip, certificate, sniErr)
	if sniErr != nil {
		if allowsTriState(classifySNIFailure(ctx, sniErr)) == TriStateFalse {
			sTC.SNIAllowsIPasSNI = TriStateFalse
		}
	} else {
		sTC.SNIAllowsIPasSNI = TriStateTrue
		if certificate != nil {
			sTC.gctx.RegisterCertificate(certificate)
			sTC.SNIIPCertificate = certificate.SerialNumber.String()
			sTC.AddCertificate(certificate)
		}
	}
}
