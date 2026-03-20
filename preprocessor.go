package main

import (
	"fmt"
	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/helpers"
	"net"
	"strings"

	"github.com/charmbracelet/log"
)

func ProcessTargetHostInputs(dnsResolver dns.DNSResolver, TargetsPath string, TargetsExplicit string, HostsPath string, HostsExplicit string, Mixed string) ([]string, []string) {

	allTargets := []string{}
	allHosts := []string{}

	// read files
	if len(TargetsPath) > 0 {
		targets, err := helpers.ParseListFile(TargetsPath)
		if err != nil {
			log.Errorf("Failed to parse Targets file:%s\n%+v", TargetsPath, err)
			return nil, nil
		}
		if len(targets) == 0 {
			log.Warn("The provided target-list file resulted in 0 targets")
		}
		allTargets = append(allTargets, targets...)
	}

	//Process inline targets
	if len(TargetsExplicit) > 0 {
		for _, v := range strings.Split(TargetsExplicit, ",") {
			allTargets = append(allTargets, strings.Trim(v, " "))
		}
	}

	//Process positional targets
	if len(Mixed) > 0 {
		for _, v := range strings.Split(Mixed, ",") {
			allTargets = append(allTargets, strings.Trim(v, " "))
		}
	}

	if len(HostsPath) > 0 {
		hosts, err := helpers.ParseListFile(HostsPath)
		if err != nil {
			log.Errorf("Failed to parse Host file:%s\n%+v", HostsPath, err)
			return nil, nil
		}
		if len(hosts) == 0 {
			log.Warn("The provided host-list file resulted in 0 hosts")
		}
		allHosts = append(allHosts, hosts...)
	}

	if len(HostsExplicit) > 0 {
		for _, v := range strings.Split(HostsExplicit, ",") {
			allHosts = append(allHosts, strings.Trim(v, " "))
		}
	}

	allTargets = helpers.RemoveDuplicate(allTargets)
	//allTargets = helpers.RemoveEmpty(allTargets)
	allTargets, expandedHostnames := targetFormatter(dnsResolver, allTargets)
	allHosts = append(allHosts, expandedHostnames...)
	allHosts = helpers.RemoveDuplicate(allHosts)
	//allTargets = helpers.RemoveEmpty(allHosts)

	return allTargets, allHosts
}

func targetFormatter(dnsResolver dns.DNSResolver, targets []string) ([]string, []string) {
	cleanedTargets := []string{}
	hostnames := []string{}
	for _, target := range targets {
		//Then the target uses CIDR notation
		//This allows the specification of targets with port in CIDR:
		//>> 10.11.10.0/24:80
		target = strings.Trim(target, " ")
		if helpers.IsCIDR(target) {
			cidr, port, err := helpers.SplitIntoCidrAndPort(target)
			if err != nil {
				log.Fatalf("Failed to parse target '%s'", target)
				continue
			}
			ips, err := helpers.ExpandCIDR(cidr)
			if err != nil {
				log.Fatalf("Failed to parse target '%s'", target)
				continue
			}
			for _, ipaddr := range ips {
				cleanedTargets = append(cleanedTargets, net.JoinHostPort(ipaddr, fmt.Sprintf("%d", port)))
			}
		} else {
			ips, hostname := EnsureIpAndPort(dnsResolver, target)
			cleanedTargets = append(cleanedTargets, ips...)
			hostnames = append(hostnames, hostname)
		}
	}
	return cleanedTargets, hostnames
}

func EnsureIpAndPort(dnsResolver dns.DNSResolver, target string) ([]string, string) {
	ret := []string{}
	hostname := ""
	port := "443"
	var err error
	if strings.Contains(target, ":") {
		target, port, err = net.SplitHostPort(target)
		if err != nil {
			if err.(*net.AddrError).Err == "missing port in address" {
				port = "443"
			} else {
				log.Errorf("Failed to parse host:port '%s'\n%+v", target, err)
				return []string{}, ""
			}
		}
	}
	var ips []string
	ips, hostname = EnsureIP(dnsResolver, target)
	for _, ip := range ips {
		ret = append(ret, net.JoinHostPort(ip, port))
	}
	return ret, hostname
}

func EnsureIP(dnsResolver dns.DNSResolver, hostname string) ([]string, string) {
	ret := []string{}
	if res := net.ParseIP(hostname); res == nil {
		if ips, err := dnsResolver.Resolve(hostname); err == nil {
			for _, ip := range ips {
				ret = append(ret, ip.String())
			}
			return ret, hostname
		} else {
			log.Errorf("Unable to resolve host '%s'. The hostname will still be used for enumeration.", hostname)
			return []string{}, hostname
		}
	} else {
		return []string{hostname}, ""
	}
}
