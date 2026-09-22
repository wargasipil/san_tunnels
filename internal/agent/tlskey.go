package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// tlsValidity is deliberately long. This certificate is pinned by fingerprint,
// not validated against a CA, so expiry buys nothing and an expired agent that
// nobody can log into is a worse outcome than a long-lived pinned key.
const tlsValidity = 10 * 365 * 24 * time.Hour

// LoadOrCreateTLSCert returns the agent's self-signed certificate, generating
// and persisting it on first run.
//
// This exists so TLS needs no setup: there is no CA to run, no ACME challenge
// to satisfy from behind NAT, and no reason to fall back to cleartext. Clients
// authenticate it by fingerprint, exactly as they already authenticate the SSH
// host key -- so the trust model is the one operators already understand from
// known_hosts, rather than a second, weaker one.
func LoadOrCreateTLSCert(certPath, keyPath string, hosts []string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return &cert, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// A half-written pair is worth reporting rather than silently
		// replacing: overwriting would change the fingerprint and lock out
		// every client that has already pinned it.
		if _, statErr := os.Stat(certPath); statErr == nil {
			return nil, fmt.Errorf("load tls keypair %s / %s: %w", certPath, keyPath, err)
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate tls key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "san_tunnels agent"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(tlsValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range tlsHosts(hosts) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal tls key: %w", err)
	}

	for _, p := range []string{certPath, keyPath} {
		if dir := filepath.Dir(p); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("create dir %s: %w", dir, err)
			}
		}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil { //nolint:gosec // a certificate is public
		return nil, fmt.Errorf("write certificate %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write tls key %s: %w", keyPath, err)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("build keypair: %w", err)
	}
	return &pair, nil
}

// tlsHosts builds the SAN list: whatever was asked for, plus loopback and this
// machine's hostname, so a locally-run agent works without configuration.
func tlsHosts(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, h := range hosts {
		add(h)
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	if hn, err := os.Hostname(); err == nil {
		add(hn)
	}
	return out
}

// CertFingerprint is the SHA-256 of the leaf certificate, formatted like an
// SSH fingerprint so the two look alike wherever they are printed together.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// LeafFingerprint returns the fingerprint of a loaded certificate.
func LeafFingerprint(cert *tls.Certificate) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", errors.New("no certificate")
	}
	return CertFingerprint(cert.Certificate[0]), nil
}
