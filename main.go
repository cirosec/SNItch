package main

import (
	"context"
	"fmt"
	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/dns"
	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/output"
	"github.com/cirosec/snitch/report"
	"github.com/cirosec/snitch/scan"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const VERSION = "1.4-dev"

var (
	plainTargets   string
	plainHostnames string
	pathTargets    string
	pathHostnames  string
	ignoredHosts   []string
	requiredHosts  []string
	threads        int
	epochs         int
	noRecon        bool
	noCRTLog       bool
	crtlogDB       string
	noPTR          bool
	noIPasSNI      bool
	noPlainHTTP    bool
	plainHTTPPort  int
	debugMode      bool
	searchHeaders  bool
	timeoutSeconds int
	dnsServer      string
	userAgent      string
	jsonlPath      string
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "SNItch [targets]",
		Short:   "Uses SNI, DNS and crt.name to test where FQDNs are really hosted, helping to identify misconfigurations",
		Version: VERSION,
		Long: `SNItch ` + VERSION + ` - © cirosec GmbH

SNItch uses SNI, DNS and crt.name to test where FQDNs are really hosted, helping to identify misconfigurations and finding unmanaged or hidden services

Quickstart:
  # Checks all A and AAAA records of that domain on port 443:
  SNItch "cirosec.de"

  # Performs recon using a hostname list on 8.8.8.8/24:443:
  SNItch -t "8.8.8.8/24:443" --host-list my_file

  # Use only supplied target and two hostnames. No further recon.
  SNItch -t "images.google.com" -d "maps.google.com" --no-recon`,
		Args: cobra.MaximumNArgs(1),
		Run:  runScan,
	}

	// Define flags
	rootCmd.Flags().StringVarP(&plainTargets, "targets", "t", "", "Comma separated list of targets in the following supported formats: domain, domain:port, IP, IP:port, CIDR, CIDR:port. If not specified, port 443 is assumed. IPv6 is supported with bracket notation (brackets are required to attach a port, e.g. [2001:db8::1]:8443). If a domain name is supplied the IPs of the DNS A-records and AAAA-records are added to the target list and the domain is moved to the hostname list")
	rootCmd.Flags().StringVarP(&plainHostnames, "hosts", "d", "", "Comma separated list of hosts to be tested. Supports FQDN or wildcard FQDNs")
	rootCmd.Flags().StringVar(&pathTargets, "target-list", "", "Path to a newline separated list of targets in the following supported formats: domain, domain:port, IP, IP:port, CIDR, CIDR:port. If not specified, port 443 is assumed.")
	rootCmd.Flags().StringVar(&pathHostnames, "host-list", "", "Path to a newline separated list of hosts to be tested. Supports FQDN or wildcard FQDNs")
	rootCmd.Flags().StringSliceVarP(&ignoredHosts, "ignore", "i", []string{}, "Comma separated list of FQDNs or wildcards which will be ignored in the scan")
	rootCmd.Flags().StringSliceVarP(&requiredHosts, "require", "r", []string{}, "Comma separated list of regular expressions that each scanned FQDN must match. Otherwise the FQDN is discarded")
	rootCmd.Flags().IntVarP(&threads, "threads", "p", 50, "The number of threads used to probe the servers. Adjust this number if IDS/WAF/Firewall/anti-DoS rules are triggered")
	rootCmd.Flags().IntVarP(&epochs, "epochs", "e", 2, "The maximum number of iterations used when scanning")
	rootCmd.Flags().BoolVar(&noRecon, "no-recon", false, "Disables all recon functionality. SNItch will not attempt to find new FQDNs")
	rootCmd.Flags().BoolVar(&noCRTLog, "no-crtlog", false, "Disables the certificate search on crt.name")
	rootCmd.Flags().StringVar(&crtlogDB, "crtlog-db", "/tmp/crtlog", "Path to the local crt.name cache directory")
	rootCmd.Flags().BoolVar(&noPTR, "no-ptr", false, "Disables reverse IP (PTR record) hostname discovery")
	rootCmd.Flags().BoolVar(&noIPasSNI, "no-ip-sni", false, "Disables sending the target IP as SNI value. Use this when targets are behind Cloudflare or similar services that block non-RFC compliant SNI requests")
	rootCmd.Flags().BoolVar(&noPlainHTTP, "no-http", false, "Disables plaintext HTTP probing of the target IP. Reveals hostnames from http->https redirects and catch-all servers, both on the HTTP port and on the target's TLS port")
	rootCmd.Flags().IntVar(&plainHTTPPort, "http-port", 80, "Port used for plaintext HTTP probing of each target IP")
	rootCmd.Flags().BoolVar(&searchHeaders, "search-headers", false, "Enables broader search for domains in all HTTP response headers, not just Location redirects")
	rootCmd.Flags().BoolVar(&debugMode, "debug", false, "Writes detailed debug output to a log file")
	rootCmd.Flags().IntVar(&timeoutSeconds, "timeout", 10, "Global timeout in seconds for all network operations (connections, TLS handshakes, HTTP requests)")
	rootCmd.Flags().StringVar(&dnsServer, "dns", "", "Custom DNS server to use instead of the system resolver (e.g. 8.8.8.8 or 1.1.1.1:53)")
	rootCmd.Flags().StringVar(&userAgent, "user-agent", "", "Custom User-Agent header for HTTP requests (default: a generic browser-like SNItch UA)")
	rootCmd.Flags().StringVar(&jsonlPath, "jsonl", "", "Write machine-readable results as JSONL to this file. Use \"-\" for stdout (suppresses the human-readable report)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// validateScanParams checks the numeric CLI flags before any work starts.
// It returns an error describing the first invalid value, if any.
func validateScanParams(threads, timeoutSeconds, epochs int) error {
	if threads < 1 {
		return fmt.Errorf("--threads/-p must be >= 1, got %d", threads)
	}
	if timeoutSeconds < 1 {
		return fmt.Errorf("--timeout must be >= 1 second, got %d", timeoutSeconds)
	}
	if epochs < 1 {
		return fmt.Errorf("--epochs/-e must be >= 1, got %d", epochs)
	}
	return nil
}

func runScan(cmd *cobra.Command, args []string) {
	if err := validateScanParams(threads, timeoutSeconds, epochs); err != nil {
		fmt.Printf("[error] %s\n", err)
		os.Exit(1)
	}

	posTargetMix := ""
	if len(args) > 0 {
		posTargetMix = args[0]
	}

	// When JSONL is written to stdout ("-"), all human-readable and progress
	// output must move to stderr so stdout stays valid JSONL. Capture the real
	// stdout first for the JSONL sink, then point the standard streams at stderr.
	jsonlStdout := os.Stdout
	if jsonlPath == "-" {
		os.Stdout = os.Stderr
		color.Output = os.Stderr
		color.Error = os.Stderr
	}

	fmt.Printf("🎩 SNItch %s - © cirosec GmbH\n", VERSION)
	dnsResolver := dns.NewDNSResolver(dnsServer)
	defer dnsResolver.Stop()
	allTargets, allHosts := ProcessTargetHostInputs(dnsResolver, pathTargets, plainTargets, pathHostnames, plainHostnames, posTargetMix)

	if len(allTargets) == 0 && len(allHosts) == 0 {
		fmt.Println("[error] No targets or hosts found. Nothing to scan.")
		fmt.Println("  Provide targets as positional argument, via -t flag, or --target-list file.")
		fmt.Println("  Provide hosts via -d flag or --host-list file.")
		return
	}

	// Cancel context on Ctrl+C so the scan stops gracefully and partial results are printed.
	// A second Ctrl+C forces an immediate exit, in case a network operation is stuck.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Print("\033[?25h") // Show cursor
		cancel()
		fmt.Print("\n[scan] Interrupt received, stopping... (press Ctrl+C again to force quit)\n")
		<-sigChan
		fmt.Print("\033[?25h") // Show cursor
		os.Exit(130)
	}()

	// Scan
	config := scan.NewConfig()
	config.Timeout = time.Duration(timeoutSeconds) * time.Second
	config.ParallelWorkers = threads
	config.UseCRTLog = !noCRTLog
	config.CrtLogDB = crtlogDB
	config.UsePTR = !noPTR
	config.DisableRecon = noRecon
	config.NoIPasSNI = noIPasSNI
	config.NoPlainHTTP = noPlainHTTP
	config.PlainHTTPPort = fmt.Sprintf("%d", plainHTTPPort)
	config.SearchHeaders = searchHeaders
	config.IgnoredHosts = helpers.MetaSplit(ignoredHosts, ",")
	config.MaxEpochs = epochs
	for _, element := range helpers.MetaSplit(requiredHosts, ",") {
		compiled, err := regexp.Compile(element)
		if err != nil {
			fmt.Printf("[error] Invalid regex in -r flag: %q: %v\n", element, err)
			os.Exit(1)
		}
		config.RequiredHosts = append(config.RequiredHosts, *compiled)
	}

	gctx := globalcontext.NewGlobalContext(dnsResolver)
	gctx.Timeout = config.Timeout
	gctx.UserAgent = userAgent
	gctx.SearchHeaders = searchHeaders

	// Debug logging
	var debugLog *debug.DebugLogger
	if debugMode {
		debugFile := fmt.Sprintf("snitch_debug_%s.log", time.Now().Format("20060102_150405"))
		var err error
		debugLog, err = debug.NewDebugLogger(debugFile)
		if err != nil {
			fmt.Printf("[debug] Failed to create debug log: %s\n", err)
		} else {
			defer debugLog.Close()
			fmt.Printf("[debug] Writing debug output to %s\n", debugFile)
		}
	} else {
		debugLog = debug.NopLogger()
	}
	gctx.DebugLog = debugLog
	debugLog.ScanConfig(allTargets, allHosts, threads, epochs, !noRecon, !noCRTLog, !noPTR)

	if dnsServer != "" {
		fmt.Printf("[config] DNS Server: %s\n", dnsServer)
	}
	if len(allHosts) == 0 {
		fmt.Printf("[config] Hosts: (none) - use -d \"host.example.com\" to add hostnames\n")
	} else {
		fmt.Printf("[config] Hosts: %s\n", strings.Join(allHosts, ", "))
	}
	if len(allTargets) == 0 {
		fmt.Printf("[config] Targets: (none)\n")
	} else {
		fmt.Printf("[config] Targets: %s\n", strings.Join(allTargets, ", "))
	}
	if len(config.IgnoredHosts) == 0 {
		fmt.Printf("[config] Ignored Hosts: (none) - use -i \"*.domain.com\" to exclude domains from the search\n")
	} else {
		fmt.Printf("[config] Ignored Hosts: %s\n", strings.Join(config.IgnoredHosts, ", "))
	}
	requiredMatchList := helpers.MetaSplit(requiredHosts, ",")
	if len(requiredMatchList) == 0 {
		fmt.Printf("[config] Required Match: (none) - use -r \"regex\" to only scan FQDNs matching the pattern\n")
	} else {
		fmt.Printf("[config] Required Match: %s\n", strings.Join(requiredMatchList, ", "))
	}

	// JSONL output. "-" writes JSONL to stdout and diverts human output to stderr.
	var jsonl *output.JSONLWriter
	if len(jsonlPath) > 0 {
		if jsonlPath == "-" {
			jsonl = output.NewStdout(jsonlStdout)
		} else {
			var err error
			jsonl, err = output.NewFile(jsonlPath)
			if err != nil {
				fmt.Printf("[error] %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("[jsonl] Writing machine-readable output to %s\n", jsonlPath)
		}
	}
	_ = jsonl.WriteConfig(report.Config{
		Type:          report.TypeConfig,
		Version:       VERSION,
		Targets:       allTargets,
		Hosts:         allHosts,
		IgnoredHosts:  config.IgnoredHosts,
		RequiredHosts: requiredMatchList,
		DNSServer:     dnsServer,
	})

	result := scan.DoScan(ctx, allHosts, allTargets, config, gctx)
	result.ShowResults(jsonl)
	result.WriteSummary(jsonl)
	_ = jsonl.Close()
}
