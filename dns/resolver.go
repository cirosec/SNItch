package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type DNSResolver interface {
	Resolve(hostname string) ([]net.IP, error)
	AddHostname(hostname string) error
	Stop()
}

type resolveResult struct {
	ips []net.IP
	err error
}

type hostResolver struct {
	mu       sync.RWMutex
	cache    map[string]resolveResult
	addChan  chan string
	stopChan chan struct{}
	stopOnce sync.Once
	resolver *net.Resolver
	lookup   func(ctx context.Context, hostname string) ([]net.IP, error)
}

// NewDNSResolver creates a new DNS resolver. If dnsServer is non-empty, all DNS
// lookups in the application (including third-party libraries) will use that server.
// The server can be specified as "IP" or "IP:port" (default port 53).
func NewDNSResolver(dnsServer string) DNSResolver {
	r := &hostResolver{
		cache:    make(map[string]resolveResult),
		addChan:  make(chan string, 1024*1024),
		stopChan: make(chan struct{}),
	}

	if dnsServer != "" {
		// Ensure host:port format
		if _, _, err := net.SplitHostPort(dnsServer); err != nil {
			dnsServer = net.JoinHostPort(dnsServer, "53")
		}
		customResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network == "" {
					network = "udp"
				}
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, dnsServer)
			},
		}
		r.resolver = customResolver
		// Override the global default so all net.LookupIP, net.LookupAddr,
		// http.DefaultTransport, and third-party libraries also use this server.
		net.DefaultResolver = customResolver
	} else {
		r.resolver = net.DefaultResolver
	}
	r.lookup = r.systemLookup

	go r.backgroundResolver()
	return r
}

// systemLookup resolves hostnames through the configured net.Resolver.
func (r *hostResolver) systemLookup(ctx context.Context, hostname string) ([]net.IP, error) {
	addrs, err := r.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}
	return ips, nil
}

func (r *hostResolver) Resolve(hostname string) ([]net.IP, error) {
	r.mu.RLock()
	result, ok := r.cache[hostname]
	r.mu.RUnlock()

	if ok {
		// Failures are cached with their error so a repeated lookup of an
		// unresolvable name reports the failure instead of an empty success.
		return result.ips, result.err
	}

	result = r.lookupIP(hostname)

	r.mu.Lock()
	r.cache[hostname] = result
	r.mu.Unlock()
	return result.ips, result.err
}

func (r *hostResolver) AddHostname(hostname string) error {
	select {
	case <-r.stopChan:
		return errors.New("dns resolver is stopped")
	default:
	}
	select {
	case r.addChan <- hostname:
		return nil
	case <-r.stopChan:
		return errors.New("dns resolver is stopped")
	}
}

func (r *hostResolver) backgroundResolver() {
	for {
		select {
		case <-r.stopChan:
			return
		case hostname := <-r.addChan:
			r.mu.RLock()
			_, ok := r.cache[hostname]
			r.mu.RUnlock()
			if !ok {
				// No entry --> lookup hostname
				result := r.lookupIP(hostname)
				r.mu.Lock()
				r.cache[hostname] = result
				r.mu.Unlock()
			}
		}
	}
}

// lookupIP resolves a hostname through the injectable lookup function with a
// deadline, so lookups cannot hang indefinitely.
func (r *hostResolver) lookupIP(hostname string) resolveResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ips, err := r.lookup(ctx, hostname)
	if err != nil {
		return resolveResult{ips: []net.IP{}, err: err}
	}
	if ips == nil {
		ips = []net.IP{}
	}
	return resolveResult{ips: ips}
}

func (r *hostResolver) Stop() {
	r.stopOnce.Do(func() { close(r.stopChan) })
}