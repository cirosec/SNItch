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
