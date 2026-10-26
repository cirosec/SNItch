package helpers

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func IsCIDR(potentialCIDR string) bool {
	return strings.Contains(potentialCIDR, "/")
}

// parseIPLiteral parses a bare or bracketed IP literal (e.g. "192.168.1.108",
// "::1" or "[::1]") into a net.IP, returning nil when it is not an IP address.
func parseIPLiteral(name string) net.IP {
	if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
		name = name[1 : len(name)-1]
	}
	return net.ParseIP(name)
}

// IsIPLiteral reports whether name is an IP address, accepting both bare and
// bracketed (IPv6) forms. Certificate SANs sometimes carry IP addresses in
// DNS-type entries, e.g. "127.0.0.1" or "[::1]".
func IsIPLiteral(name string) bool {
	return parseIPLiteral(name) != nil
}

// CanonicalCertName normalizes a certificate name for display and comparison:
// IP literals (including bracketed IPv6 like "[::1]") become their canonical
// form so they deduplicate against the certificate's IP SANs; any other name is
// returned unchanged.
func CanonicalCertName(name string) string {
	if ip := parseIPLiteral(name); ip != nil {
		return ip.String()
	}
	return name
}

func SplitIntoCidrAndPort(cidrWithPort string) (string, int, error) {
	if !IsCIDR(cidrWithPort) {
		return "", -1, fmt.Errorf("not a CIDR with port")
	}
	port := -1
	var err error
	s := strings.Split(cidrWithPort, "/")
	if len(s) != 2 {
		return "", port, fmt.Errorf("multiple or no CIDR ranges supplied")
	}
	remainder := strings.Split(s[1], ":")
	suffix := ""
	if len(remainder) > 2 {
		return "", port, fmt.Errorf("multiple ports supplied")
	} else if len(remainder) == 1 {
		port = 443
	} else { //==2 as 0 can not be
		suffix = remainder[1]
		port, err = strconv.Atoi(suffix)
		if err != nil {
			return "", port, err
		}
	}
	return strings.TrimSuffix(cidrWithPort, ":"+suffix), port, nil
}

func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := ipnet.Mask.Size()
	if shift := bits - ones; shift > 16 {
		count := "more than 65536"
		if shift < 64 {
			count = strconv.FormatUint(uint64(1)<<uint(shift), 10)
		}
		return nil, fmt.Errorf("CIDR %s contains %s addresses, exceeding the limit of 65536; specify a smaller range", cidr, count)
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func IsPortOpen(host string, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}
