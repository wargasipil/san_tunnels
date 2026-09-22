package agent_test

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wargasipil/san_tunnels/internal/client"
)

// safeBuffer collects session output from the ssh read goroutine.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// waitForOutput blocks until want appears in the session output, so a test can
// act on the shell being established rather than on a guess about timing.
func waitForOutput(t *testing.T, out *safeBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in session output; got %q", want, out.String())
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestInteractivePTYSession exercises the path a human actually uses: a PTY is
// allocated on the target, a shell runs on it, and typed input comes back as
// terminal output through the tunnel.
func TestInteractivePTYSession(t *testing.T) { eachTransport(t, testInteractivePTYSession) }

func testInteractivePTYSession(t *testing.T, tr client.Transport) {
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

	if err := sess.RequestPty("xterm-256color", 40, 120, gossh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	var out safeBuffer
	sess.Stdout = &out
	sess.Stderr = &out
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}

	if err := sess.Shell(); err != nil {
		t.Fatalf("start shell: %v", err)
	}

	// Enter is CR, not LF. That is what a terminal sends and what the line
	// discipline on the far side is waiting for; LF leaves the command sitting
	// unsubmitted on the prompt.
	if _, err := io.WriteString(stdin, "echo tunnel-marker\r"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.WriteString(stdin, "exit\r"); err != nil {
		t.Fatalf("write exit: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("pty session never ended; output so far: %q", out.String())
	}

	if !strings.Contains(out.String(), "tunnel-marker") {
		t.Fatalf("shell output did not contain the marker; got %q", out.String())
	}
}

// A resize must reach the far side. The shell learns its new size from the
// kernel, so this asserts the request is accepted and the session survives it.
func TestPTYResize(t *testing.T) { eachTransport(t, testPTYResize) }

func testPTYResize(t *testing.T, tr client.Transport) {
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

	if err := sess.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	var out safeBuffer
	sess.Stdout = &out
	sess.Stderr = &out
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("start shell: %v", err)
	}

	// Resize only once the shell is actually up.
	//
	// gliderlabs/ssh v0.3.8 races on the pty between Session.Pty(), which
	// copies *sess.pty (session.go:212), and its request loop writing
	// sess.pty.Window on a window-change (session.go:352). The session
	// handler runs in a goroutine the loop spawns while it keeps going, so a
	// resize that arrives before the handler has read the pty races it.
	//
	// That is an upstream bug on an unexported field and nothing here can fix
	// it; see "A race in gliderlabs" in the design doc. Waiting for output
	// proves the read already happened, and resizing an established session
	// is what a real client does anyway.
	if _, err := io.WriteString(stdin, "echo before-resize\r"); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitForOutput(t, &out, "before-resize")

	if err := sess.WindowChange(50, 200); err != nil {
		t.Fatalf("window change: %v", err)
	}

	if _, err := io.WriteString(stdin, "echo after-resize\r"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.WriteString(stdin, "exit\r"); err != nil {
		t.Fatalf("write exit: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("session never ended after resize; output: %q", out.String())
	}
	if !strings.Contains(out.String(), "after-resize") {
		t.Fatalf("session did not survive the resize; got %q", out.String())
	}
}
