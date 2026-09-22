package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wargasipil/san_tunnels/internal/agent"
	"github.com/wargasipil/san_tunnels/internal/client"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

// transports is the matrix the end-to-end tests run over.
//
// Both doors onto the agent must behave the same -- same SSH sessions, same
// exit codes, same half-close, same errors -- because that sameness is the
// whole claim of having two of them. Running one suite twice is what keeps
// the WebSocket path from becoming the shallowly-tested one.
var transports = []client.Transport{client.TransportConnect, client.TransportWS}

// eachTransport runs fn once per transport, as a subtest named for it.
func eachTransport(t *testing.T, fn func(t *testing.T, tr client.Transport)) {
	t.Helper()
	for _, tr := range transports {
		t.Run(string(tr), func(t *testing.T) { fn(t, tr) })
	}
}

type harness struct {
	target  client.Target
	hostPub gossh.PublicKey
	signer  gossh.Signer
}

// newHarness starts a real agent over TLS and returns a client pointed at it,
// with one authorized key.
func newHarness(t *testing.T, endpoints map[string]string, token string, tr client.Transport) *harness {
	t.Helper()
	dir := t.TempDir()

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
		t.Fatalf("load authorized_keys: %v", err)
	}
	if authorized.Len() != 1 {
		t.Fatalf("loaded %d keys, want 1", authorized.Len())
	}

	sshServer, err := agent.NewSSHServer(agent.SSHOptions{
		HostKey: hostKey, Authorized: authorized, Log: quiet(),
	})
	if err != nil {
		t.Fatalf("ssh server: %v", err)
	}
	svc, err := agent.NewService(sshServer, endpoints, quiet())
	if err != nil {
		t.Fatalf("service: %v", err)
	}

	srv := httptest.NewUnstartedServer(agent.Handler(agent.HandlerOptions{
		Service: svc, Token: token, Log: quiet(),
	}))
	srv.EnableHTTP2 = true
	// Advertise both protocols, as a real Go server serving TLS does.
	// httptest would otherwise offer only "h2", and a WebSocket client --
	// which must ask for http/1.1, since an Upgrade cannot ride on h2 --
	// would fail ALPN before it ever reached the handler.
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}} //nolint:gosec // test server
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &harness{
		target: client.Target{
			Name: "test-agent", URL: srv.URL, Token: token,
			Insecure: true, Transport: tr,
		},
		hostPub: hostKey.PublicKey(),
		signer:  userKey,
	}
}

// sshThroughTunnel does what `ssh` does: open the tunnel, then handshake over
// it. Nothing between here and the agent can read the session.
func (h *harness) sshThroughTunnel(t *testing.T, signer gossh.Signer, hostKey gossh.PublicKey) (*gossh.Client, error) {
	t.Helper()

	conn, err := client.Open(context.Background(), h.target, agent.ShellEndpoint)
	if err != nil {
		return nil, err
	}

	cc, chans, reqs, err := gossh.NewClientConn(conn, "san_tunnels", &gossh.ClientConfig{
		User:            "tester",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.FixedHostKey(hostKey),
		Timeout:         20 * time.Second,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	cl := gossh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { _ = cl.Close() })
	return cl, nil
}

// The headline test: a genuine SSH session, end to end, over the tunnel.
func TestSSHSessionThroughTunnel(t *testing.T) { eachTransport(t, testSSHSession) }

func testSSHSession(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "", tr)

	cl, err := h.sshThroughTunnel(t, h.signer, h.hostPub)
	if err != nil {
		t.Fatalf("ssh handshake through tunnel: %v", err)
	}

	sess, err := cl.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("echo hello")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// A real ssh client holds stdin open for the lifetime of the command, so the
// agent must not wait on it to finish.
//
// Session.Output closes stdin immediately, which is why it cannot catch this:
// the command has to be run with stdin genuinely open, the way `ssh host ls`
// does it.
func TestExecCompletesWhileStdinStaysOpen(t *testing.T) {
	eachTransport(t, testExecCompletesWhileStdinStaysOpen)
}

func testExecCompletesWhileStdinStaysOpen(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "", tr)

	cl, err := h.sshThroughTunnel(t, h.signer, h.hostPub)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	pr, pw := io.Pipe()
	defer pw.Close() // deliberately never closed while the command runs
	sess.Stdin = pr

	var out safeBuffer
	sess.Stdout = &out

	done := make(chan error, 1)
	go func() { done <- sess.Run("echo still-here") }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("command never finished with stdin held open: the agent is waiting on a stdin copy that will never end")
	}

	if got := strings.TrimSpace(out.String()); got != "still-here" {
		t.Fatalf("got %q, want %q", got, "still-here")
	}
}

// A non-zero exit must reach the caller, or scripts calling through the tunnel
// cannot tell success from failure.
func TestExitCodePropagates(t *testing.T) { eachTransport(t, testExitCodePropagates) }

func testExitCodePropagates(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "", tr)

	cl, err := h.sshThroughTunnel(t, h.signer, h.hostPub)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	err = sess.Run("exit 3")
	var ee *gossh.ExitError
	if !asExitError(err, &ee) {
		t.Fatalf("got %v, want an ExitError", err)
	}
	if ee.ExitStatus() != 3 {
		t.Fatalf("exit status %d, want 3", ee.ExitStatus())
	}
}

func asExitError(err error, target **gossh.ExitError) bool {
	ee, ok := err.(*gossh.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// Host-key pinning is what stops an intermediary substituting its own key and
// reading the session, so a wrong key must abort the handshake.
func TestWrongHostKeyRejected(t *testing.T) { eachTransport(t, testWrongHostKeyRejected) }

func testWrongHostKeyRejected(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "", tr)
	other := newSigner(t)

	_, err := h.sshThroughTunnel(t, h.signer, other.PublicKey())
	if err == nil {
		t.Fatal("handshake succeeded against the wrong host key")
	}
	if !strings.Contains(err.Error(), "host key") {
		t.Fatalf("got %v, want a host key mismatch", err)
	}
}

func TestUnauthorizedKeyRejected(t *testing.T) { eachTransport(t, testUnauthorizedKeyRejected) }

func testUnauthorizedKeyRejected(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "", tr)
	stranger := newSigner(t)

	_, err := h.sshThroughTunnel(t, stranger, h.hostPub)
	if err == nil {
		t.Fatal("handshake succeeded with an unauthorized key")
	}
	if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("got %v, want an authentication failure", err)
	}
}

// An endpoint outside the allowlist must be refused: accepting a free-form
// address would make the agent an open relay.
func TestUnknownEndpointRejected(t *testing.T) { eachTransport(t, testUnknownEndpointRejected) }

func testUnknownEndpointRejected(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "", tr)

	_, err := client.Open(context.Background(), h.target, "not-allowlisted")
	if err == nil {
		t.Fatal("opened an endpoint that is not in the allowlist")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("got %v, want the error to mention the allowlist", err)
	}
}

// The same tunnel must carry an ordinary TCP service, which is what makes the
// name true rather than it being an SSH-only tool.
func TestTCPEndpointForwarding(t *testing.T) { eachTransport(t, testTCPEndpointForwarding) }

func testTCPEndpointForwarding(t *testing.T, tr client.Transport) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}()
		}
	}()

	h := newHarness(t, map[string]string{"echo": ln.Addr().String()}, "", tr)

	conn, err := client.Open(context.Background(), h.target, "echo")
	if err != nil {
		t.Fatalf("open echo endpoint: %v", err)
	}
	defer conn.Close()

	want := "ping through the tunnel"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("got %q, want %q", buf, want)
	}
}

func TestTokenRequired(t *testing.T) { eachTransport(t, testTokenRequired) }

func testTokenRequired(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "correct-token", tr)

	bad := h.target
	bad.Token = "wrong-token"
	if _, err := client.Open(context.Background(), bad, agent.ShellEndpoint); err == nil {
		t.Fatal("opened a tunnel with the wrong token")
	}

	conn, err := client.Open(context.Background(), h.target, agent.ShellEndpoint)
	if err != nil {
		t.Fatalf("correct token was refused: %v", err)
	}
	conn.Close()
}

// The probe must pass on a path that really works, over either door.
func TestCheckPasses(t *testing.T) { eachTransport(t, testCheckPasses) }

func testCheckPasses(t *testing.T, tr client.Transport) {
	h := newHarness(t, nil, "", tr)

	if err := client.Check(context.Background(), h.target, 15*time.Second); err != nil {
		t.Fatalf("check failed on a working %s path: %v", tr, err)
	}
}

// An HTTP/1.1 request must be refused loudly. Without this the request body is
// buffered by whatever downgraded it, the first `open` never arrives, and the
// session hangs with no error anywhere.
func TestHTTP11RejectedLoudly(t *testing.T) {
	dir := t.TempDir()
	hostKey, err := agent.LoadOrCreateHostKey(filepath.Join(dir, "host_key"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	authorized, err := agent.LoadAuthorizedKeys(filepath.Join(dir, "authorized_keys"))
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

	// Plain httptest: HTTP/1.1, exactly what a downgrading proxy delivers.
	srv := httptest.NewServer(agent.Handler(agent.HandlerOptions{Service: svc, Log: quiet()}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/san.tunnels.v1.TunnelService/Forward", "application/connect+proto", strings.NewReader(""))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusHTTPVersionNotSupported {
		t.Fatalf("status %d, want %d", resp.StatusCode, http.StatusHTTPVersionNotSupported)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "HTTP/2") {
		t.Fatalf("body %q should name the real problem", body)
	}
}

// The other half of the previous test, and the reason the WebSocket door
// exists: the very HTTP/1.1 server that refuses a Connect stream carries a
// full SSH session over /ws without complaint.
func TestWebSocketWorksOverHTTP11(t *testing.T) {
	dir := t.TempDir()

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

	// No EnableHTTP2, no TLS: HTTP/1.1 and nothing else.
	srv := httptest.NewServer(agent.Handler(agent.HandlerOptions{Service: svc, Log: quiet()}))
	defer srv.Close()

	target := client.Target{Name: "ws-agent", URL: srv.URL, Transport: client.TransportWS}
	conn, err := client.Open(context.Background(), target, agent.ShellEndpoint)
	if err != nil {
		t.Fatalf("open websocket tunnel over HTTP/1.1: %v", err)
	}
	defer conn.Close()

	cc, chans, reqs, err := gossh.NewClientConn(conn, "san_tunnels", &gossh.ClientConfig{
		User:            "tester",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(userKey)},
		HostKeyCallback: gossh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         20 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh handshake over websocket: %v", err)
	}
	cl := gossh.NewClient(cc, chans, reqs)
	defer cl.Close()

	sess, err := cl.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("echo over-ws")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "over-ws" {
		t.Fatalf("got %q, want %q", got, "over-ws")
	}
}

// Half-close must cross the tunnel on both transports.
//
// This is the one place they genuinely differ underneath: Connect gets the
// FIN from CloseRequest, while WebSocket has no such frame and relies on the
// close-write control message in package wsconn. An endpoint that reads until
// EOF before replying -- which is what plenty of TCP protocols do -- hangs
// forever if that message is missing, so the parity is worth asserting.
func TestHalfCloseReachesEndpoint(t *testing.T) { eachTransport(t, testHalfCloseReachesEndpoint) }

func testHalfCloseReachesEndpoint(t *testing.T, tr client.Transport) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Reads to EOF, then reports how much it got. Without a propagated
	// half-close the ReadAll never returns and this test times out.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, err := io.ReadAll(c)
				if err != nil {
					return
				}
				fmt.Fprintf(c, "got %d", len(b))
			}()
		}
	}()

	h := newHarness(t, map[string]string{"drain": ln.Addr().String()}, "", tr)

	conn, err := client.Open(context.Background(), h.target, "drain")
	if err != nil {
		t.Fatalf("open drain endpoint: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	done := make(chan struct{})
	var reply []byte
	var readErr error
	go func() {
		defer close(done)
		reply, readErr = io.ReadAll(conn)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("endpoint never saw end-of-input: the half-close did not cross the tunnel")
	}
	if readErr != nil {
		t.Fatalf("read reply: %v", readErr)
	}
	if got := strings.TrimSpace(string(reply)); got != "got 10" {
		t.Fatalf("got %q, want %q", got, "got 10")
	}
}

// A stalled duplex probe must name both the cause and the way out.
//
// This is the half-duplex symptom exactly: the stream is accepted, and no
// reply ever comes. Refusing to fall back to WebSocket automatically is only
// defensible if the manual route is signposted, so the message has to carry
// it -- and a message nothing asserts is a message that rots.
func TestStalledProbeNamesTheRemedy(t *testing.T) {
	// Accept the request and never answer, the way a proxy buffering the
	// whole request body leaves the agent's first reply forever pending.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	target := client.Target{Name: "stalled-box", URL: srv.URL, Insecure: true}
	err := client.Check(context.Background(), target, 750*time.Millisecond)
	if err == nil {
		t.Fatal("a probe that never got a reply reported success")
	}

	for _, want := range []string{
		"duplex probe",   // what failed
		"HTTP/1.1",       // why, in terms the operator can act on
		"--transport ws", // the way out
		"stalled-box",    // which agent to change in the config
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("probe failure message does not mention %q; got:\n%s", want, err)
		}
	}
}

// The reserved name must not be silently overridable by config.
func TestShellEndpointIsReserved(t *testing.T) {
	dir := t.TempDir()
	hostKey, _ := agent.LoadOrCreateHostKey(filepath.Join(dir, "host_key"))
	authorized, _ := agent.LoadAuthorizedKeys(filepath.Join(dir, "authorized_keys"))
	sshServer, err := agent.NewSSHServer(agent.SSHOptions{HostKey: hostKey, Authorized: authorized, Log: quiet()})
	if err != nil {
		t.Fatalf("ssh server: %v", err)
	}

	_, err = agent.NewService(sshServer, map[string]string{agent.ShellEndpoint: "127.0.0.1:22"}, quiet())
	if err == nil {
		t.Fatal("accepted a config that redefines the reserved shell endpoint")
	}
}
