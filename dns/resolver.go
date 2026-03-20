package dns

import (
	"context"
	"net"
	"sync"
	"time"
)

type DNSResolver interface {
	Resolve(hostname string) ([]net.IP, error)
	AddHostname(hostname string) error
	Stop()
}

type hostResolver struct {
	mu       sync.RWMutex
	cache    map[string][]net.IP
	addChan  chan string
	stopChan chan struct{}
	resolver *net.Resolver
}

// NewDNSResolver creates a new DNS resolver. If dnsServer is non-empty, all DNS
// lookups in the application (including third-party libraries) will use that server.
// The server can be specified as "IP" or "IP:port" (default port 53).
func NewDNSResolver(dnsServer string) DNSResolver {
	r := &hostResolver{
		cache:    make(map[string][]net.IP),
		addChan:  make(chan string, 1024*1024),
		stopChan: make(chan struct{}, 10),
	}

	if dnsServer != "" {
		// Ensure host:port format
		if _, _, err := net.SplitHostPort(dnsServer); err != nil {
			dnsServer = net.JoinHostPort(dnsServer, "53")
		}
		customResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		r.resolver = customResolver
		// Override the global default so all net.LookupIP, net.LookupAddr,
		// http.DefaultTransport, and third-party libraries also use this server.
		net.DefaultResolver = customResolver
	} else {
		r.resolver = net.DefaultResolver
	}

	go r.backgroundResolver()
	return r
}

func (r *hostResolver) Resolve(hostname string) ([]net.IP, error) {
	r.mu.RLock()
	ips, ok := r.cache[hostname]
	r.mu.RUnlock()

	if ok {
		return ips, nil
	}

	ips, err := r.lookupIP(hostname)
	if err != nil {
		ips = []net.IP{}
	}

	r.mu.Lock()
	r.cache[hostname] = ips
	r.mu.Unlock()
	return ips, err
}

func (r *hostResolver) AddHostname(hostname string) error {
	r.addChan <- hostname
	return nil
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
				ips, err := r.lookupIP(hostname)
				if err != nil {
					ips = []net.IP{}
				}
				r.mu.Lock()
				r.cache[hostname] = ips
				r.mu.Unlock()
			}
		}
	}
}

// lookupIP resolves a hostname using the configured resolver.
func (r *hostResolver) lookupIP(hostname string) ([]net.IP, error) {
	addrs, err := r.resolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}
	return ips, nil
}

func (r *hostResolver) Stop() {
	close(r.stopChan)
}
