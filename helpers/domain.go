package helpers

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func FQDNToSLD(FQDN string) (string, error) {
	// Converts lol.example.com to example.com
	// Handles multi-part TLDs like co.uk, com.au correctly:
	//   foo.co.uk -> foo.co.uk
	//   bar.example.co.uk -> example.co.uk
	FQDN = strings.TrimPrefix(FQDN, "*.")
	sld, err := publicsuffix.EffectiveTLDPlusOne(FQDN)
	if err != nil {
		return "", fmt.Errorf("unable to convert FQDN to SLD: %w", err)
	}
	return sld, nil
}

func GetLabelByLevelFromFQDN(fqdn string, level int) (string, string) {
	cleanFqdn := strings.TrimPrefix(fqdn, "*.")
	sld, err := publicsuffix.EffectiveTLDPlusOne(cleanFqdn)
	if err != nil {
		// Fallback: treat entire string as the SLD
		return "", fqdn
	}
	sldParts := strings.Split(sld, ".")
	tmp := strings.Split(fqdn, ".")
	if len(tmp) <= len(sldParts) {
		return "", fqdn
	}
	if level == 0 { // Return SLD
		return "", sld
	}
	sldDepth := len(sldParts)
	idx := len(tmp) - (level + sldDepth)
	last := ""
	if idx >= 0 {
		last = tmp[idx]
	}
	return last, strings.Join(tmp[idx+1:], ".")
}
