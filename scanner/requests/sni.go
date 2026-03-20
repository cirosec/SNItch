package requests

import (
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
// cached/custom DNS results instead of falling back to the system resolver.
func resolveTarget(resolver dns.DNSResolver, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	if net.ParseIP(host) != nil {
		return target // already an IP
	}
	ips, err := resolver.Resolve(host)
	if err != nil || len(ips) == 0 {
		return target
	}
	return net.JoinHostPort(ips[0].String(), port)
}

// buildSNIExtension manually constructs an SNI extension with the given server name,
// bypassing the IP address check that both stdlib and uTLS enforce.
func buildSNIExtension(serverName string) *utls.GenericExtension {
	// TLS extension structure for SNI (extension type 0x0000):
	// - Server Name List Length (2 bytes)
	//   - Server Name Type (1 byte): 0x00 = host_name
	//   - Server Name Length (2 bytes)
	//   - Server Name (variable)
	nameBytes := []byte(serverName)
	nameLen := len(nameBytes)

	// Server Name List: type(1) + length(2) + name(nameLen)
	serverNameListLen := 1 + 2 + nameLen
	// Extension data: list length(2) + server name list
	extDataLen := 2 + serverNameListLen

	data := make([]byte, extDataLen)
	// Server Name List Length
	data[0] = byte(serverNameListLen >> 8)
	data[1] = byte(serverNameListLen)
	// Server Name Type: host_name (0)
	data[2] = 0
	// Server Name Length
	data[3] = byte(nameLen >> 8)
	data[4] = byte(nameLen)
	// Server Name
	copy(data[5:], nameBytes)

	return &utls.GenericExtension{
		Id:   0, // 0x0000 = server_name extension
		Data: data,
	}
}

func MakeSNIRequest(resolver dns.DNSResolver, target, SNI string, timeout time.Duration, forceSNIextension bool) (*x509.Certificate, error) {
	cfg := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "dummy-value",
	}

	netConn, err := net.DialTimeout("tcp", resolveTarget(resolver, target), timeout)
	if err != nil {
		_, err = ErrorHandlerConn(err)
		return nil, err
	}
	defer netConn.Close()

	conn := utls.UClient(netConn, cfg, utls.HelloCustom)
	defer conn.Close()

	extensions := []utls.TLSExtension{}
	if SNI != "" || forceSNIextension{
		extensions = append(extensions, buildSNIExtension(SNI))
	}
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

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if err := conn.Handshake(); err != nil {
		_, err = ErrorHandlerConn(err)
		return nil, err
	}

	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, errors.New("no peer certificates returned")
	}

	return peerCerts[0], nil
}
