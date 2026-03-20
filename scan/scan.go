package scan

import (
	"context"
	"fmt"
	"github.com/cirosec/snitch/crtsh"
	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/reverseip"
	"net"
	"sync"
	"time"

	"github.com/briandowns/spinner"
)

func DoScan(ctx context.Context, hosts []string, targets []string, config *ScanConfig, gctx *globalcontext.GlobalContext) *ScanManager {
	allTargetsBefore := targets
	targets = ParallelFilterOfflineTargets(ctx, targets, gctx.DebugLog, config.Timeout)

	// Log which targets were filtered out
	onlineSet := make(map[string]bool, len(targets))
	for _, t := range targets {
		onlineSet[t] = true
	}
	for _, t := range allTargetsBefore {
		if !onlineSet[t] {
			gctx.DebugLog.TargetOffline(t)
		}
	}

	scan := NewScanManager(config, gctx)
	for _, host := range hosts {
		scan.container.AddFQDN(host)
		gctx.DNSresolver.AddHostname(host)
	}
	for _, target := range targets {
		scan.container.AddTarget(target)
	}

	newTargets := []string{}
	for _, t := range targets {
		ip, _, _ := net.SplitHostPort(t)
		newTargets = append(newTargets, ip)
	}
	go gctx.Whois.Query(ctx, newTargets)

	isFilteredHost := func(host string) bool {
		if helpers.WildcardOrFullMatch(host, config.AllIgnoredHosts()) {
			return true
		}
		if len(config.RequiredHosts) > 0 {
			for _, expr := range config.RequiredHosts {
				if expr.MatchString(host) {
					return false
				}
			}
			return true
		}
		return false
	}

	// One-time PTR recon: target IPs never change across iterations
	if !config.DisableRecon && config.UsePTR {
		for _, host := range reverseip.LookupByTargetIPs(ctx, newTargets, isFilteredHost, gctx.DebugLog) {
			gctx.DebugLog.HostAdded("ptr", host)
			scan.container.AddFQDN(host)
		}
	}

	cancelled := false
	iteration := 0
	for {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		iteration++
		if iteration > config.MaxEpochs {
			break
		}
		unscannedHosts := scan.container.GetUnscannedHosts()
		if len(unscannedHosts) == 0 {
			// If no new hosts are in the scan, abort, as no hosts will be found from now on.
			break
		}
		gctx.DebugLog.Iteration(iteration, config.MaxEpochs, len(unscannedHosts))

		s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		s.HideCursor = false
		s.Start()
		s.Suffix = fmt.Sprintf(" [%d/%d] Iteration", iteration, config.MaxEpochs)
		scan.ParallelRun(ctx, s)
		s.Stop()

		if ctx.Err() != nil {
			cancelled = true
			break
		}

		if config.DisableRecon {
			//Skip all recon steps
			continue
		}

		// Add all hosts from the collected Certificates
		certHosts := gctx.CertificateHostnames()
		if len(certHosts) > 0 {
			// Log per-cert recon details
			certSnapshot := gctx.GetCertificatesSnapshot()
			occurrences := gctx.GetCertificateOccurrenceSnapshot()
			for sn, cert := range certSnapshot {
				hostnames := make([]string, len(cert.DNSNames)+1)
				copy(hostnames, cert.DNSNames)
				hostnames[len(cert.DNSNames)] = cert.Subject.CommonName
				gctx.DebugLog.CertRecon(sn, occurrences[sn], hostnames)
			}
		}

		var crtshHosts []string
		if config.UseCRTSH {
			crtshHosts = crtsh.SearchByList(ctx, unscannedHosts, isFilteredHost, gctx.DebugLog, gctx.UserAgent, config.CrtshDB)
		}

		redirectHosts := gctx.RedirectHostnames()
		if len(redirectHosts) > 0 {
			gctx.DebugLog.RedirectRecon(redirectHosts)
		}

		var headerHosts []string
		if config.SearchHeaders {
			headerHosts = gctx.HeaderHostnames()
			if len(headerHosts) > 0 {
				gctx.DebugLog.HeaderRecon(headerHosts)
			}
		}

		reconHosts := certHosts
		reconHosts = append(reconHosts, crtshHosts...)
		reconHosts = append(reconHosts, redirectHosts...)
		reconHosts = append(reconHosts, headerHosts...)
		for _, host := range reconHosts {
			if !isFilteredHost(host) {
				gctx.DebugLog.HostAdded("recon", host)
				scan.container.AddFQDN(host)
			}
		}
	}

	if cancelled {
		fmt.Println("\n[scan] Interrupted. Printing partial results...")
	}

	unscannedHosts := scan.container.GetUnscannedHosts()
	if len(unscannedHosts) > 0 && !cancelled {
		fmt.Printf("[scan] 🔥 Not all identified hosts have been scanned. You can increase the number of iterations using the CLI flag -e (e.g. -e %d).\n", config.MaxEpochs+1)
		fmt.Printf("[scan] 🔥 Unscanned hosts (increase epochs): %v\n", unscannedHosts)
	}
	return scan
}

func ParallelFilterOfflineTargets(ctx context.Context, targets []string, debugLog *debug.DebugLogger, timeout time.Duration) []string {
	var wg sync.WaitGroup
	results := make(chan string, len(targets))
	OpenTargets := []string{}

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			host, port, err := net.SplitHostPort(target)
			if err != nil {
				return
			}
			d := &net.Dialer{Timeout: timeout}
			conn, dialErr := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
			if dialErr != nil {
				return
			}
			conn.Close()
			debugLog.TargetOnline(target)
			results <- target
		}(target)
	}

	wg.Wait()
	close(results)

	for result := range results {
		OpenTargets = append(OpenTargets, result)
	}

	return OpenTargets
}
