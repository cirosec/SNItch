package helpers

import "testing"

func TestDNS(t *testing.T) {
	if !DNSDomainInArray([]string{"*.cirosec.de", "cirosec.de"}, "someapp.cirosec.de") {
		t.Fail()
	}
}
