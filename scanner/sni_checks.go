package scanner

import (
	"github.com/charmbracelet/log"

	"net"
	"net/url"
	"strings"

	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/scanner/requests"
)

// check for random SNIs and compare results
func (sTC *ScannerRootResult) SNICheckRandom() {
	random1 := helpers.RandStringBytes(10) + ".com"
	certificate, err1 := requests.MakeSNIRequest(
		sTC.gctx.DNSresolver,
		sTC.Target,
		random1, // SNI
		sTC.gctx.Timeout,
		false,
	)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, random1, certificate, err1)
	if err1 != nil {
		if _, ok := err1.(*url.Error); ok {
			sTC.SNIDisconnectsOnRandom = TriStateTrue
		} else if match, _ := requests.ErrorHandlerConn(err1); match {
			sTC.SNIDisconnectsOnRandom = TriStateTrue
		} else {
			log.Printf("[%s] Received unknown error in SNICheckRandom for sni '%s': %s", sTC.Target, random1, err1.Error())
			return // TODO?
		}
	} else {
		sTC.SNIDisconnectsOnRandom = TriStateFalse
		sTC.AddCertificate(certificate)
		sTC.SetFallbackCertificate(certificate)
	}
}

// checks for empty or missing SNI fields
func (sTC *ScannerRootResult) checkNoSNI() {
	certificate, err := requests.MakeSNIRequest(
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
	} else {
		sTC.SNIAllowsMissing = TriStateFalse
	}
}

// checkEmptySNIWithExtension sends the SNI extension with an empty server name value
func (sTC *ScannerRootResult) checkEmptySNIWithExtension() {
	certificate, err := requests.MakeSNIRequest(
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
	} else {
		sTC.SNIAllowsEmptyWithExt = TriStateFalse
	}
}

func (sTC *ScannerRootResult) checkSNIWithSpaces() {
	certificate, err := requests.MakeSNIRequest(
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
	} else {
		sTC.SNIAllowsEmpty = TriStateFalse
	}
}

func (sHC *ScannerHostnameResult) checkSNI(target string) {
	certificate, err := requests.MakeSNIRequest(
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
	}
}

func (sWC *ScannerSubdomainResult) checkSNI(target string) {
	domain := strings.TrimPrefix(sWC.wildcardDomain, "*.")
	sni := helpers.RandStringBytes(4) + "." + domain
	certificate, err := requests.MakeSNIRequest(
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
	}
}

// checkSNIWithIP sends the target's IP address as the SNI value
func (sTC *ScannerRootResult) checkSNIWithIP() {
	ip, _, err := net.SplitHostPort(sTC.Target)
	if err != nil {
		return
	}
	certificate, sniErr := requests.MakeSNIRequest(sTC.gctx.DNSresolver, sTC.Target, ip, sTC.gctx.Timeout, true)
	sTC.gctx.DebugLog.SNIRequest(sTC.Target, ip, certificate, sniErr)
	if sniErr != nil {
		sTC.SNIAllowsIPasSNI = TriStateFalse
	} else {
		sTC.SNIAllowsIPasSNI = TriStateTrue
		if certificate != nil {
			sTC.gctx.RegisterCertificate(certificate)
			sTC.SNIIPCertificate = certificate.SerialNumber.String()
			sTC.AddCertificate(certificate)
		}
	}
}
