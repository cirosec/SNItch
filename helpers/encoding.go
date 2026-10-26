package helpers

import (
	"strings"

	"golang.org/x/net/idna"
)

// EncodingVariants returns de-duplicated alternative encodings of host that a
// TLS server might treat differently from the literal hostname. The input
// itself is never included. A trailing dot, uppercased form and the IDN
// A-label/U-label counterparts are considered.
func EncodingVariants(host string) []string {
	base := strings.TrimSuffix(host, ".")

	candidates := []string{base + "."}
	if upper := strings.ToUpper(base); upper != base {
		candidates = append(candidates, upper)
	}
	if ascii, err := idna.ToASCII(base); err == nil && ascii != base {
		candidates = append(candidates, ascii)
	}
	if unicode, err := idna.ToUnicode(base); err == nil && unicode != base {
		candidates = append(candidates, unicode)
	}

	candidates = RemoveDuplicate(RemoveEmpty(candidates))
	variants := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate != host {
			variants = append(variants, candidate)
		}
	}
	return variants
}
