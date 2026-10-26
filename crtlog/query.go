package crtlog

import (
	"context"
	"fmt"
	"github.com/cirosec/snitch/debug"
	"github.com/cirosec/snitch/helpers"
	"slices"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/jpillora/go-tld"
)

type fnFilter func(string) bool

func SearchByList(ctx context.Context, hostnames []string, isFilteredDomain fnFilter, debugLog *debug.DebugLogger, userAgent string, dbPath string) []string {
	printAfter := ""
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Start()
	domains := []string{}
	prefix := ""
	// Get the proper domain from the provided FQDN
	for _, hostname := range hostnames {
		if hostname == "" || hostname == "." || hostname == "*." {
			// The domain is on the ignore list or is a technical domain in the tree.
			continue
		}
		specialHostname := "https://" + hostname
		specialHostname = strings.ReplaceAll(specialHostname, "*.", "") // Remove wildcards
		// This is required, as this library only accepts domains with protocol prefix
		u, err := tld.Parse(specialHostname)
		if err != nil {
			prefix = prefix + fmt.Sprintf("[crt.name] %s Failed to parse '%s'\n", color.RedString("╳"), specialHostname)
			s.Prefix = prefix
		} else {
			if u.TLD != "" && u.Domain != "" {
				domains = append(domains, u.Domain+"."+u.TLD)
			}
		}
	}
	//Apply Ignored Hostnames filtering
	filteredDomains := []string{}
	for _, domain := range helpers.RemoveDuplicate(domains) {
		if !isFilteredDomain(domain) {
			filteredDomains = append(filteredDomains, domain)
		}
	}
	slices.Sort(filteredDomains)
	collectedHostnames := []string{}

	prefix = prefix + "[crt.name] 🔺 you can ignore domains using -i \"*.domain.com\"\n"
	prefix = prefix + fmt.Sprintf("[crt.name] ⚡ %s\n", strings.Join(filteredDomains, ","))
	printAfter = fmt.Sprintf("[crt.name] ⚡ %s\n", strings.Join(filteredDomains, ","))
	s.Prefix = prefix
	domains = filteredDomains

	db := NewCrtLog(dbPath)
	defer db.Close()

	for _, domain := range domains {
		if ctx.Err() != nil {
			break
		}
		s.Suffix = " Fetching certificate data for " + domain
		results, err := db.Get(ctx, domain, userAgent)
		for _, r := range results {
			// Remove results which contain spaces, as such results cannot be valid FQDNs
			//Remove results, which contain upper case letters, as the domains are always stored in lower case
			if strings.Contains(r, " ") || strings.ToLower(r) != r {
				continue
			}
			collectedHostnames = append(collectedHostnames, r)
		}

		if err != nil {
			debugLog.CrtLogResult(domain, nil, err)
			s.Prefix = s.Prefix + fmt.Sprintf("%s %s %v\n", color.RedString("╳"), domain, err)
		} else {
			debugLog.CrtLogResult(domain, results, nil)
			s.Prefix = s.Prefix + fmt.Sprintf("%s %s Found %d hostnames\n", color.GreenString("✔"), domain, len(results))
		}
	}
	s.Stop()
	fmt.Printf("%s", printAfter)
	return collectedHostnames
}
