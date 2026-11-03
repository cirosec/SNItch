package main

import (
	"runtime/debug"
	"strings"
)

// Builds made with `go install ...@vX.Y.Z` get no ldflags, so take the
// version from the module info embedded by the Go toolchain.
func init() {
	if VERSION != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			VERSION = strings.TrimPrefix(v, "v")
		}
	}
}
