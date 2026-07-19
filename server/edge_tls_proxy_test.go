//go:build unit

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

const upstreamHostname = "stargate.test.local"

// selfSignedForHostname builds a CA-less self-signed cert valid only for
// upstreamHostname -- one DNS SAN, no IP SANs, mirroring the Let's Encrypt cert
// Envoy presents in staging.
func selfSignedForHostname(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: upstreamHostname},
		DNSNames:              []string{upstreamHostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	return cert, pool
}

// startEchoUpstream stands in for Envoy: TLS on 127.0.0.1, h2 in ALPN, echoing
// whatever it receives.
func startEchoUpstream(t *testing.T, cert tls.Certificate) *url.URL {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}

	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	u, err := url.Parse("https://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	return u
}

// runProxy starts the L4 proxy on an ephemeral port and returns its address.
func runProxy(t *testing.T, upstream *url.URL, pool *x509.CertPool, serverName string) string {
	t.Helper()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}

	addr := probe.Addr().String()
	probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go RunEdgeTLSProxyServer(ctx, addr, upstream, pool, nil, serverName)

	// Give the listener a moment to bind.
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	return addr
}

// roundTrip writes a probe payload through the proxy and reports whether it
// echoed back, which only happens if the upstream TLS handshake succeeded.
func roundTrip(t *testing.T, proxyAddr string) error {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	return nil
}

// Without server-name the proxy verifies the upstream cert against the dial
// address (127.0.0.1), which the hostname-only cert can't satisfy.
func TestTLSProxyFailsWithoutServerName(t *testing.T) {
	cert, pool := selfSignedForHostname(t)
	upstream := startEchoUpstream(t, cert)
	proxyAddr := runProxy(t, upstream, pool, "")

	if err := roundTrip(t, proxyAddr); err == nil {
		t.Fatal("expected the upstream handshake to fail against an IP dial address, but traffic flowed")
	}
}

// With server-name set, SNI and hostname verification both target the name on
// the cert, so the handshake completes even though we dialed an IP.
func TestTLSProxySucceedsWithServerName(t *testing.T) {
	cert, pool := selfSignedForHostname(t)
	upstream := startEchoUpstream(t, cert)
	proxyAddr := runProxy(t, upstream, pool, upstreamHostname)

	if err := roundTrip(t, proxyAddr); err != nil {
		t.Fatalf("expected traffic to flow with server-name set, got: %v", err)
	}
}
