package agent_test

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wargasipil/san_tunnels/internal/agent"
	"github.com/wargasipil/san_tunnels/internal/client"
)

// tlsAgent starts an agent serving a generated self-signed certificate from
// dir, and returns the client target plus the certificate fingerprint.
func tlsAgent(t *testing.T, dir string) (client.Target, gossh.Signer, string) {
	t.Helper()

	hostKey, err := agent.LoadOrCreateHostKey(filepath.Join(dir, "host_key"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	userKey := newSigner(t)
	authPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authPath, gossh.MarshalAuthorizedKey(userKey.PublicKey()), 0o600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
	authorized, err := agent.LoadAuthorizedKeys(authPath)
	if err != nil {
		t.Fatalf("authorized keys: %v", err)
	}
	sshServer, err := agent.NewSSHServer(agent.SSHOptions{HostKey: hostKey, Authorized: authorized, Log: quiet()})
	if err != nil {
		t.Fatalf("ssh server: %v", err)
	}
	svc, err := agent.NewService(sshServer, nil, quiet())
	if err != nil {
		t.Fatalf("service: %v", err)
	}

	cert, err := agent.LoadOrCreateTLSCert(
		filepath.Join(dir, "tls_cert.pem"), filepath.Join(dir, "tls_key.pem"), nil)
	if err != nil {
		t.Fatalf("tls cert: %v", err)
	}
	fp, err := agent.LeafFingerprint(cert)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	srv := httptest.NewUnstartedServer(agent.Handler(agent.HandlerOptions{Service: svc, Log: quiet()}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{ //nolint:gosec // test server
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return client.Target{Name: "pinned-agent", URL: srv.URL}, userKey, fp
}

// A generated certificate must survive a restart unchanged: regenerating it
// would change the fingerprint and lock out every client that pinned it.
func TestGeneratedCertIsStable(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls_cert.pem")
	keyPath := filepath.Join(dir, "tls_key.pem")

	first, err := agent.LoadOrCreateTLSCert(certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	fp1, _ := agent.LeafFingerprint(first)

	second, err := agent.LoadOrCreateTLSCert(certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	fp2, _ := agent.LeafFingerprint(second)

	if fp1 != fp2 {
		t.Fatalf("fingerprint changed across loads: %s then %s", fp1, fp2)
	}
	if !strings.HasPrefix(fp1, "SHA256:") {
		t.Fatalf("fingerprint %q should be SSH-shaped", fp1)
	}
}

func TestPinnedFingerprintAccepted(t *testing.T) {
	target, _, fp := tlsAgent(t, t.TempDir())
	target.TLSFingerprint = fp

	conn, err := client.Open(context.Background(), target, agent.ShellEndpoint)
	if err != nil {
		t.Fatalf("correct pin was refused: %v", err)
	}
	conn.Close()
}

// The whole point of pinning: a certificate that is not the pinned one must be
// refused, however well-formed it is.
func TestWrongPinRefused(t *testing.T) {
	target, _, _ := tlsAgent(t, t.TempDir())
	_, other, _ := tlsAgent(t, t.TempDir())
	_ = other

	// A valid fingerprint, just not this agent's.
	target.TLSFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	_, err := client.Open(context.Background(), target, agent.ShellEndpoint)
	if err == nil {
		t.Fatal("connected to an agent whose certificate does not match the pin")
	}
	if !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("got %v, want the error to explain the pin mismatch", err)
	}
}

// Trust on first use: the first connection records the certificate, and a
// later connection presenting a different one is refused.
func TestTrustOnFirstUseThenRefusesChange(t *testing.T) {
	store := filepath.Join(t.TempDir(), "known_agents.json")
	known, err := client.LoadKnownAgents(store)
	if err != nil {
		t.Fatalf("known agents: %v", err)
	}

	target, _, fp := tlsAgent(t, t.TempDir())
	target.Known = known

	var trusted string
	target.OnTrust = func(_, fingerprint string) { trusted = fingerprint }

	conn, err := client.Open(context.Background(), target, agent.ShellEndpoint)
	if err != nil {
		t.Fatalf("first connection refused: %v", err)
	}
	conn.Close()

	if trusted != fp {
		t.Fatalf("recorded %q, want %q", trusted, fp)
	}
	if got := known.Get(target.Name); got != fp {
		t.Fatalf("store holds %q, want %q", got, fp)
	}

	// A second agent, same name, different certificate: an impersonation.
	imposter, _, impostorFP := tlsAgent(t, t.TempDir())
	if impostorFP == fp {
		t.Fatal("two generated certificates collided")
	}
	imposter.Name = target.Name
	imposter.Known = known

	_, err = client.Open(context.Background(), imposter, agent.ShellEndpoint)
	if err == nil {
		t.Fatal("accepted a different certificate for an already-known agent")
	}
	if !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("got %v, want the error to explain the pin mismatch", err)
	}
}

// A recorded pin must survive a restart of the client.
func TestKnownAgentsPersist(t *testing.T) {
	store := filepath.Join(t.TempDir(), "known_agents.json")

	first, err := client.LoadKnownAgents(store)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := first.Add("box-01", "SHA256:example"); err != nil {
		t.Fatalf("add: %v", err)
	}

	reloaded, err := client.LoadKnownAgents(store)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.Get("box-01"); got != "SHA256:example" {
		t.Fatalf("got %q after reload", got)
	}
}
