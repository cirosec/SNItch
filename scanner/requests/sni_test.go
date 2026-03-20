package requests

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cirosec/snitch/dns"
)

func testResolver() dns.DNSResolver {
	return dns.NewDNSResolver("")
}
func TestSNIOnlyTLD(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", ":443", 10*time.Second, true)
	if err != nil {
		t.Error(err)
		return
	}
}
func TestSNIEmptyExtension(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", "", 10*time.Second, true)
	if err != nil {
		t.Error(err)
		return
	}
}
func TestSNIwithSpace(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", " ", 10*time.Second, true)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestSNIwithDoubleSpace(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", "  ", 10*time.Second, true)
	if err != nil {
		t.Error(err)
		return
	}
}
func TestSNIwithIllegalChar(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", "$", 10*time.Second, true)
	if err != nil {
		t.Error(err)
		return
	}
}
func TestSNINoExtension(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", "", 10*time.Second, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestSNIwithIP(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", "1.1.0.0", 10*time.Second, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestSNINormal(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", "cirosec.de", 10*time.Second, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestWrongSNIHostname(t *testing.T) {
	_, err := MakeSNIRequest(testResolver(), "cirosec.de:443", "cirosec.de", 10*time.Second, false)
	if err != nil {
		switch {
		case errors.Is(err, ErrTLSProtocol):
			fmt.Printf("All ok")
		default:
			fmt.Printf("unexpected error: %s\n", err)
		}
		return
	}
}
