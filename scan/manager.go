package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/helpers"
	"github.com/cirosec/snitch/models"
	"github.com/cirosec/snitch/output"
	"github.com/cirosec/snitch/report"
	"github.com/cirosec/snitch/scanner"
	"github.com/cirosec/snitch/tree"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"golang.org/x/sync/errgroup"
)

var ErrEmptyQueue = errors.New("queue is empty. Expected error")

type ScanItem struct {
	hostname string
	targets  []string
}
type ScanManager struct {
	container *ScanContext
	gctx      *globalcontext.GlobalContext
	config    *ScanConfig
	queue     chan ScanItem

	// Summary state, filled in by DoScan.
	iterations     int
	cancelled      bool
	unscannedHosts []string
}

func NewScanManager(config *ScanConfig, gctx *globalcontext.GlobalContext) *ScanManager {
	return &ScanManager{container: NewScanContext(config), queue: make(chan ScanItem, 1024*1024), config: config, gctx: gctx}
}

func (s *ScanManager) EnqueueAll(ctx context.Context, hostnames []string) {
	chunkSize := 3
	for _, hostname := range hostnames {
		for _, chunk := range helpers.ChunkBy(s.container.targets, chunkSize) {
			select {
			case s.queue <- ScanItem{hostname, chunk}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *ScanManager) ParallelRun(ctx context.Context, spinner *spinner.Spinner) error {
	staticSpinnerPrefix := spinner.Suffix
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.config.ParallelWorkers)

	// A fresh queue per run: workers must drain it while it is filled, or a
	// run with more jobs than the buffer deadlocks on send.
	s.queue = make(chan ScanItem, 1024*1024)
	hostnames := s.container.GetUnscannedHosts()
	expected := len(hostnames) * len(helpers.ChunkBy(s.container.targets, 3))
	go func() {
		s.EnqueueAll(gctx, hostnames)
		close(s.queue)
	}()

	i := 0
	for job := range s.queue {
		if gctx.Err() != nil {
			break
		}
		i++
		spinner.Suffix = staticSpinnerPrefix + fmt.Sprintf(" - %d/%d Tasks", i, expected)
		g.Go(func() error {
			thisHost := job.hostname
			thisTargets := job.targets
			for _, target := range thisTargets {
				// string is wildcard placeholder *.FQDN
				if strings.HasPrefix(thisHost, "*.") {
					thisScan := scanner.NewScannerSubdomainResult(thisHost, target, s.gctx)
					thisScan.Run(gctx)
					// A cancelled run leaves a partial result; don't persist it
					// as a finding.
					if gctx.Err() != nil {
						return nil
					}
					s.container.AddResult(target, thisHost, thisScan)
				} else if thisHost == "." { //string is ROOT placeholder which does tests per target without specific hostname
					thisScan := scanner.NewScannerRootResult(target, s.gctx, s.config.NoIPasSNI, s.config.NoPlainHTTP, s.config.PlainHTTPPort)
					thisScan.Run(gctx)
					if gctx.Err() != nil {
						return nil
					}
					s.container.AddResult(target, thisHost, thisScan)
				} else { // string is FQDN
					thisScan := scanner.NewSNIHostnameResult(thisHost, target, s.gctx)
					thisScan.Run(gctx)
					if gctx.Err() != nil {
						return nil
					}
					s.container.AddResult(target, thisHost, thisScan)
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		fmt.Printf("%+v", err)
		return err
	}
	// No error occurred, flag all hosts.
	s.container.FlagAllHosts()
	return nil
}

// Collect builds the per-target result tables once, so both the human printer
// and the JSONL exporter can consume identical data.
func (s *ScanManager) Collect() map[string]*tree.MiniTable {
	forest := tree.ForestBuilder(s.container.targets, s.container.results)
	tables := make(map[string]*tree.MiniTable, len(s.container.targets))
	for _, target := range s.container.targets {
		tables[target] = forest[target].BuildTable(s.gctx, &tree.PrintConfig{Root: forest[target], Target: target, AllTargets: s.container.targets})
	}
	return tables
}

// ShowResults prints the human-readable report and, when jsonl is non-nil,
// writes the matching machine-readable records from the same built rows.
func (s *ScanManager) ShowResults(jsonl *output.JSONLWriter) {
	tables := s.Collect()

	PrintFCertificates(s.gctx)
	s.writeCertificates(jsonl)

	for _, target := range s.container.targets {
		tree.PrintTargetHeading(target)
		table := tables[target]
		table.Print()
		for _, row := range table.Rows() {
			_ = jsonl.WriteHost(row.ToReport(target))
		}
	}

	tree.PrintLegend()
	s.gctx.Whois.Print(s.container.targets)
	s.writeIPs(jsonl)
}

// WriteSummary emits the final summary record.
func (s *ScanManager) WriteSummary(jsonl *output.JSONLWriter) {
	if jsonl == nil {
		return
	}
	_ = jsonl.WriteSummary(report.Summary{
		Type:           report.TypeSummary,
		Iterations:     s.iterations,
		Cancelled:      s.cancelled,
		UnscannedHosts: s.unscannedHosts,
	})
}

func (s *ScanManager) writeCertificates(jsonl *output.JSONLWriter) {
	if jsonl == nil {
		return
	}
	certificates := s.gctx.GetCertificatesSnapshot()
	occurrences := s.gctx.GetCertificateOccurrenceSnapshot()
	for sn, cert := range certificates {
		names := []string{}
		for _, n := range cert.DNSNames {
			names = append(names, helpers.CanonicalCertName(n))
		}
		names = append(names, helpers.CanonicalCertName(cert.Subject.CommonName))
		for _, ip := range cert.IPAddresses {
			names = append(names, ip.String())
		}
		_ = jsonl.WriteCertificate(report.Certificate{
			Type:          report.TypeCertificate,
			Serial:        sn,
			NotAfter:      cert.NotAfter.Format("2006-01-02"),
			Expired:       !cert.NotAfter.After(time.Now()),
			Names:         helpers.RemoveDuplicate(names),
			Emails:        helpers.CertEmailAddresses(cert),
			Organizations: helpers.CertOrganizations(cert),
			Targets:       occurrences[sn],
		})
	}
}

func (s *ScanManager) writeIPs(jsonl *output.JSONLWriter) {
	if jsonl == nil {
		return
	}
	seen := map[string]bool{}
	for _, target := range s.container.targets {
		ip, _, err := net.SplitHostPort(target)
		if err != nil || seen[ip] {
			continue
		}
		seen[ip] = true
		record := report.IP{Type: report.TypeIP, IP: ip, DynamicCertificates: s.targetReflectsSNI(target)}
		if info := s.gctx.Whois.Get(ip); info != nil {
			record.Name = info.Name
			record.Range = info.Range
		}
		_ = jsonl.WriteIP(record)
	}
}

// targetReflectsSNI reports whether the root scan of target observed a server
// that echoes the requested SNI back in its certificate, i.e. a dynamic
// (per-SNI) certificate issuer.
func (s *ScanManager) targetReflectsSNI(target string) bool {
	result, ok := s.container.results[models.ScanContextResultKey{Target: target, Host: "."}]
	if !ok {
		return false
	}
	root, ok := result.(*scanner.ScannerRootResult)
	return ok && root.SNIReflectsName == scanner.TriStateTrue
}

func PrintFCertificates(gctx *globalcontext.GlobalContext) {
	certColor := color.New(color.FgBlack, color.BgWhite).SprintFunc()
	fmt.Print("\n")
	fmt.Println(helpers.CenterString(" Observed Certificates ", 50, "─"))

	// Get thread-safe snapshots
	certificates := gctx.GetCertificatesSnapshot()
	occurrences := gctx.GetCertificateOccurrenceSnapshot()

	for sn, cert := range certificates {
		expire := cert.NotAfter
		expire_string := expire.Format("2006-01-02")
		if expire.After(time.Now()) {
			//All ok
			expire_string = color.GreenString(expire_string)
		} else {
			expire_string = color.RedString(expire_string)
		}
		hostnames := []string{}
		for _, n := range cert.DNSNames {
			hostnames = append(hostnames, helpers.CanonicalCertName(n))
		}
		hostnames = append(hostnames, helpers.CanonicalCertName(cert.Subject.CommonName))
		for _, ip := range cert.IPAddresses {
			hostnames = append(hostnames, ip.String())
		}
		all_names := helpers.RemoveDuplicate(hostnames)
		shortSerialNumber := sn
		if len(sn) > 10 {
			shortSerialNumber = sn[:10]
		}

		line := fmt.Sprintf("%s [%s] (%s)", certColor(fmt.Sprintf("%-10s", shortSerialNumber)), expire_string, strings.Join(all_names, ", "))
		// The organization and email metadata is often the only place a device
		// vendor's identity (and domain) appears; surface it next to the names.
		if orgs := helpers.CertOrganizations(cert); len(orgs) > 0 {
			line += fmt.Sprintf("  [%s]", strings.Join(orgs, ", "))
		}
		if emails := helpers.CertEmailAddresses(cert); len(emails) > 0 {
			line += fmt.Sprintf("  <%s>", strings.Join(emails, ", "))
		}
		fmt.Println(line)
		fmt.Printf("⤷ %s\n", strings.Join(occurrences[sn], ", "))
	}
	fmt.Print("\n")
}
