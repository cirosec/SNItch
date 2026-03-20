package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cirosec/snitch/globalcontext"
	"github.com/cirosec/snitch/helpers"
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
}

func NewScanManager(config *ScanConfig, gctx *globalcontext.GlobalContext) *ScanManager {
	return &ScanManager{container: NewScanContext(config), queue: make(chan ScanItem, 1024*1024), config: config, gctx: gctx}
}

func (s *ScanManager) EnqueueAll(hostnames []string) {
	chunkSize := 3
	for _, hostname := range hostnames {
		for _, chunk := range helpers.ChunkBy(s.container.targets, chunkSize) {
			s.queue <- ScanItem{hostname, chunk}
		}
	}
}

func (s *ScanManager) ParallelRun(ctx context.Context, spinner *spinner.Spinner) error {
	s.EnqueueAll(s.container.GetUnscannedHosts())
	staticSpinnerPrefix := spinner.Suffix
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.config.ParallelWorkers)
	items := len(s.queue)
	for i := 0; i < items; i++ {
		if gctx.Err() != nil {
			break
		}
		spinner.Suffix = staticSpinnerPrefix + fmt.Sprintf(" - %d/%d Tasks", i+1, items)
		g.Go(func() error {
			thisHost := ""
			thisTargets := []string{}
			select {
			case job := <-s.queue:
				thisHost = job.hostname
				thisTargets = job.targets
			default:
				return ErrEmptyQueue
			}
			for _, target := range thisTargets {
				// string is wildcard placeholder *.FQDN
				if strings.HasPrefix(thisHost, "*.") {
					thisScan := scanner.NewScannerSubdomainResult(thisHost, target, s.gctx)
					thisScan.Run(gctx)
					s.container.AddResult(target, thisHost, thisScan)
				} else if thisHost == "." { //string is ROOT placeholder which does tests per target without specific hostname
					thisScan := scanner.NewScannerRootResult(target, s.gctx, s.config.NoIPasSNI)
					thisScan.Run(gctx)
					s.container.AddResult(target, thisHost, thisScan)
				} else { // string is FQDN
					thisScan := scanner.NewSNIHostnameResult(thisHost, target, s.gctx)
					thisScan.Run(gctx)
					s.container.AddResult(target, thisHost, thisScan)
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		if !errors.Is(err, ErrEmptyQueue) {
			fmt.Printf("%+v", err)
			return err
		}
	}
	// No error occurred, flag all hosts.
	s.container.FlagAllHosts()
	return nil
}

func (s *ScanManager) ShowResults() {
	// Print certificate results
	PrintFCertificates(s.gctx)

	// Print SNI results
	collection := tree.ForestBuilder(s.container.targets, s.container.results)
	for key, target := range collection {
		target.TablePrint(s.gctx, &tree.PrintConfig{Root: target, Target: key, AllTargets: s.container.targets})
	}

	// Print legend once after all tables
	tree.PrintLegend()

	s.gctx.Whois.Print(s.container.targets)
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
		hostnames = append(hostnames, cert.DNSNames...)
		hostnames = append(hostnames, cert.Subject.CommonName)
		for _, ip := range cert.IPAddresses {
			hostnames = append(hostnames, ip.String())
		}
		all_names := helpers.RemoveDuplicate(hostnames)
		shortSerialNumber := sn
		if len(sn) > 10 {
			shortSerialNumber = sn[:10]
		}

		fmt.Printf("%s [%s] (%s)\n", certColor(fmt.Sprintf("%-10s", shortSerialNumber)), expire_string, strings.Join(all_names, ", "))
		fmt.Printf("⤷ %s\n", strings.Join(occurrences[sn], ", "))
	}
	fmt.Print("\n")
}
