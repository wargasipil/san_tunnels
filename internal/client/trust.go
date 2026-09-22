package client

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// KnownAgents records which certificate we saw for an agent the first time we
// connected, and refuses a different one afterwards.
//
// This is trust on first use, the same model as ssh's StrictHostKeyChecking
// accept-new and the same file shape as known_hosts. It exists so a self-signed
// agent certificate needs no copying of fingerprints by hand: the first
// connection on a trusted network establishes the pin, and every later one is
// verified against it.
//
// It is weaker than a fingerprint pinned in advance -- an attacker present for
// that very first connection is trusted forever -- so a fingerprint in the
// config always wins when one is set.
type KnownAgents struct {
	mu   sync.Mutex
	path string
	m    map[string]string
}

// DefaultKnownAgentsPath sits beside the client config.
func DefaultKnownAgentsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(dir, "san_tunnels", "known_agents.json"), nil
}

// LoadKnownAgents reads path; a missing file is an empty store.
func LoadKnownAgents(path string) (*KnownAgents, error) {
	k := &KnownAgents{path: path, m: map[string]string{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read known agents %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &k.m); err != nil {
		return nil, fmt.Errorf("parse known agents %s: %w", path, err)
	}
	if k.m == nil {
		k.m = map[string]string{}
	}
	return k, nil
}

// Get returns the pinned fingerprint for name, if any.
func (k *KnownAgents) Get(name string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[name]
}

// Add records a fingerprint and persists the store.
func (k *KnownAgents) Add(name, fingerprint string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.m[name] = fingerprint

	if dir := filepath.Dir(k.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}
	b, err := json.MarshalIndent(k.m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode known agents: %w", err)
	}
	if err := os.WriteFile(k.path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write known agents %s: %w", k.path, err)
	}
	return nil
}

// Names lists known agents, sorted.
func (k *KnownAgents) Names() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]string, 0, len(k.m))
	for n := range k.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Fingerprint formats a certificate's SHA-256 the way the agent prints it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// tlsVerifier carries a certificate rejection out to the caller.
//
// Neither http2.Transport nor the WebSocket dialler surfaces the error a
// VerifyPeerCertificate callback returns: the handshake simply fails and the
// caller sees something like "write envelope: EOF". A pin mismatch is exactly
// the moment a precise message matters most, so it is captured here and
// substituted for the transport's generic failure.
type tlsVerifier struct {
	mu  sync.Mutex
	err error
}

func (v *tlsVerifier) set(err error) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.err = err
}

func (v *tlsVerifier) get() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.err
}

// record stores err for enrich and returns it, for use inside a verify
// callback whose return value the transport discards.
func record(v *tlsVerifier, err error) error {
	v.set(err)
	return err
}

// enrich replaces a transport error with the certificate rejection behind it.
func enrich(v *tlsVerifier, err error) error {
	if ve := v.get(); ve != nil {
		return ve
	}
	return err
}

// tlsConfigFor builds the client TLS config for a target.
//
// Three modes, in descending order of strength:
//   - a fingerprint in the config: pinned, nothing else accepted;
//   - a known-agents entry, or trust on first use when there is none;
//   - Insecure: no verification at all, development only.
//
// Normal CA verification is used when the agent presents a certificate that
// chains to a real root, so an operator who does have proper certificates is
// not forced onto pinning.
func tlsConfigFor(t Target, known *KnownAgents, onTrust func(name, fingerprint string), v *tlsVerifier) *tls.Config {
	if t.Insecure {
		return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, dev only
	}

	pinned := t.TLSFingerprint
	if pinned == "" && known != nil {
		pinned = known.Get(t.Name)
	}

	// Verification is taken over wholesale, because a self-signed agent
	// certificate can never satisfy the default path; the callback below does
	// the CA check itself and falls back to the pin.
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("agent presented no certificate")
			}
			got := Fingerprint(rawCerts[0])

			if pinned != "" {
				if got == pinned {
					return nil
				}
				return record(v, fmt.Errorf(
					"agent %q presented certificate %s, but %s is pinned.\n"+
						"Either the agent's certificate was regenerated, or something is "+
						"impersonating it. If the change was expected, remove the entry for "+
						"%q from your known_agents.json (or update tls_fingerprint) and reconnect",
					t.Name, got, pinned, t.Name))
			}

			// Nothing pinned yet. Accept a certificate that verifies normally;
			// otherwise record this one and trust it from here on.
			if err := verifyAgainstSystemRoots(t, rawCerts); err == nil {
				return nil
			}
			if known != nil {
				if err := known.Add(t.Name, got); err != nil {
					return fmt.Errorf("record agent fingerprint: %w", err)
				}
			}
			if onTrust != nil {
				onTrust(t.Name, got)
			}
			return nil
		},
	}
}

// wsTLSConfig is tlsConfigFor with ALPN forced to HTTP/1.1, because an Upgrade
// handshake cannot ride on h2.
func wsTLSConfig(t Target, v *tlsVerifier) *tls.Config {
	c := tlsConfigFor(t, t.Known, t.OnTrust, v)
	c.NextProtos = []string{"http/1.1"}
	return c
}

// verifyAgainstSystemRoots runs the standard chain check that
// InsecureSkipVerify turned off.
func verifyAgainstSystemRoots(t Target, rawCerts [][]byte) error {
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}

	opts := x509.VerifyOptions{
		DNSName:       hostOf(t.URL),
		Intermediates: x509.NewCertPool(),
	}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(opts)
	return err
}
