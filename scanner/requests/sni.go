package requests

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cirosec/snitch/dns"

	utls "github.com/refraction-networking/utls"
)

// resolveTarget resolves the target through the application's DNS cache if the
// host portion is a hostname rather than an IP. This ensures all connections use
// cached/custom DNS results instead of falling back to the system resolver. When
// the resolver fails or returns no addresses, an error is returned instead of
// silently dialing the raw hostname via the system resolver.
func resolveTarget(resolver dns.DNSResolver, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, nil
	}
	if net.ParseIP(host) != nil {
		return target, nil // already an IP
	}
	ips, err := resolver.Resolve(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no addresses returned for %q", host)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// buildSNIExtensionNames manually constructs an SNI extension encoding a proper
// RFC 6066 ServerNameList with all given names, bypassing the IP address check
// that both stdlib and uTLS enforce. An empty name is encoded as a zero-length
// host_name entry.
func buildSNIExtensionNames(names []string) *utls.GenericExtension {
	// TLS extension structure for SNI (extension type 0x0000):
	// - Server Name List Length (2 bytes)
	//   repeated for every name:
	//   - Server Name Type (1 byte): 0x00 = host_name
	//   - Server Name Length (2 bytes)
	//   - Server Name (variable)
	listLen := 0
	for _, name := range names {
		listLen += 1 + 2 + len(name)
	}

	// Extension data: list length(2) + server name list
	data := make([]byte, 2+listLen)
	// Server Name List Length
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)
	offset := 2
	for _, name := range names {
		nameBytes := []byte(name)
		// Server Name Type: host_name (0)
		data[offset] = 0
		// Server Name Length
		data[offset+1] = byte(len(nameBytes) >> 8)
		data[offset+2] = byte(len(nameBytes))
		// Server Name
		copy(data[offset+3:], nameBytes)
		offset += 3 + len(nameBytes)
	}

	return &utls.GenericExtension{
		Id:   0, // 0x0000 = server_name extension
		Data: data,
	}
}

// buildSNIExtension constructs a single-name SNI extension, preserving the
// original zero-length host_name behavior for an empty serverName.
func buildSNIExtension(serverName string) *utls.GenericExtension {
	return buildSNIExtensionNames([]string{serverName})
}

// buildSNIExtensions returns the server_name extension(s) to include for the
// given names. The extension is sent when forceExtension is set or any name is
// non-empty. With duplicateExtension a second, identical extension is emitted.
func buildSNIExtensions(names []string, forceExtension, duplicateExtension bool) []utls.TLSExtension {
	send := forceExtension
	for _, name := range names {
		if name != "" {
			send = true
			break
		}
	}
	if !send {
		return nil
	}
	extensions := []utls.TLSExtension{buildSNIExtensionNames(names)}
	if duplicateExtension {
		extensions = append(extensions, buildSNIExtensionNames(names))
	}
	return extensions
}

// SNIRequestOptions controls the server_name extension sent in a crafted
// ClientHello.
type SNIRequestOptions struct {
	Names              []string // Values placed in the RFC 6066 ServerNameList
	ForceExtension     bool     // Send the extension even with empty/no names
	DuplicateExtension bool     // Emit a second, identical server_name extension
}

// MakeSNIRequest preserves the original single-name API and delegates to
// MakeSNIRequestOpts.
func MakeSNIRequest(ctx context.Context, resolver dns.DNSResolver, target, SNI string, timeout time.Duration, forceSNIextension bool) (*x509.Certificate, error) {
	return MakeSNIRequestOpts(ctx, resolver, target, SNIRequestOptions{
		Names:          []string{SNI},
		ForceExtension: forceSNIextension,
	}, timeout)
}

func MakeSNIRequestOpts(ctx context.Context, resolver dns.DNSResolver, target string, opts SNIRequestOptions, timeout time.Duration) (*x509.Certificate, error) {
	cfg := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "dummy-value",
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	dialer := &net.Dialer{Timeout: timeout}
	addr, resolveErr := resolveTarget(resolver, target)
	if resolveErr != nil {
		return nil, resolveErr
	}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		_, err = ErrorHandlerConn(err)
		return nil, err
	}
	defer netConn.Close()

	conn := utls.UClient(netConn, cfg, utls.HelloCustom)
	defer conn.Close()

	extensions := buildSNIExtensions(opts.Names, opts.ForceExtension, opts.DuplicateExtension)
	extensions = append(extensions,
		&utls.SupportedVersionsExtension{Versions: []uint16{
			utls.VersionTLS13, utls.VersionTLS12, utls.VersionTLS11, utls.VersionTLS10,
		}},
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
		}},
		&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.ECDSAWithSHA1,
			utls.PSSWithSHA256,
			utls.PSSWithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA256,
			utls.PKCS1WithSHA384,
			utls.PKCS1WithSHA512,
			utls.PKCS1WithSHA1,
			utls.Ed25519,
		}},
		&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
			{Group: utls.X25519},
		}},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
		&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
	)

	spec := &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: []uint16{
			// TLS 1.3
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			// TLS 1.2 ECDHE
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			utls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			// TLS 1.2 DHE
			utls.FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
			utls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
			utls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			utls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			// RSA key exchange
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_RSA_WITH_RC4_128_SHA,
			utls.FAKE_TLS_RSA_WITH_RC4_128_MD5,
		},
		Extensions: extensions,
	}

	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("failed to apply utls preset: %w", err)
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if err := conn.HandshakeContext(ctx); err != nil {
		_, err = ErrorHandlerConn(err)
		return nil, err
	}

	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, errors.New("no peer certificates returned")
	}

	return peerCerts[0], nil
}
