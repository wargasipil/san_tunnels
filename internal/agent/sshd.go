package agent

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/aymanbagabas/go-pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// drainGrace bounds how long we wait for a shell's final output after it
// exits. Windows ConPTY never reports EOF on its output handle, so this cannot
// be an unbounded wait.
const drainGrace = 250 * time.Millisecond

// SSHServer is the embedded SSH server. It never listens: connections arrive
// as net.Conn values lifted off a tunnel stream and are handed to HandleConn.
type SSHServer struct {
	srv   *ssh.Server
	log   *slog.Logger
	shell string
}

// SSHOptions configures the embedded server.
type SSHOptions struct {
	HostKey    gossh.Signer
	Authorized *AuthorizedKeys
	// Shell overrides the login shell. Empty means the platform default.
	Shell string
	Log   *slog.Logger
}

// NewSSHServer builds the embedded SSH server.
func NewSSHServer(o SSHOptions) (*SSHServer, error) {
	if o.HostKey == nil {
		return nil, errors.New("a host key is required")
	}
	if o.Authorized == nil {
		return nil, errors.New("an authorized key list is required")
	}
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	shell := o.Shell
	if shell == "" {
		shell = defaultShell()
	}

	s := &SSHServer{log: log, shell: shell}
	s.srv = &ssh.Server{
		Handler:     s.handleSession,
		HostSigners: []ssh.Signer{o.HostKey},

		// These must be set explicitly. gliderlabs populates them from the
		// package defaults in ensureHandlers(), which only runs on the Serve()
		// path -- and we never call Serve, because nothing listens. Leaving
		// them nil makes every session request fail with "unsupported channel
		// type" after an otherwise successful handshake.
		ChannelHandlers:   cloneChannelHandlers(),
		RequestHandlers:   cloneRequestHandlers(),
		SubsystemHandlers: cloneSubsystemHandlers(),
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			ok := o.Authorized.Has(key)
			s.log.Info("ssh auth",
				"user", ctx.User(),
				"fingerprint", gossh.FingerprintSHA256(key),
				"accepted", ok,
			)
			return ok
		},
	}
	return s, nil
}

// HandleConn serves one SSH connection and returns when the session ends.
func (s *SSHServer) HandleConn(conn net.Conn) { s.srv.HandleConn(conn) }

// The handler maps are copied rather than shared, so registering a subsystem
// (sftp, later) on one server cannot mutate the package-level defaults.

func cloneChannelHandlers() map[string]ssh.ChannelHandler {
	m := make(map[string]ssh.ChannelHandler, len(ssh.DefaultChannelHandlers))
	for k, v := range ssh.DefaultChannelHandlers {
		m[k] = v
	}
	return m
}

func cloneRequestHandlers() map[string]ssh.RequestHandler {
	m := make(map[string]ssh.RequestHandler, len(ssh.DefaultRequestHandlers))
	for k, v := range ssh.DefaultRequestHandlers {
		m[k] = v
	}
	return m
}

func cloneSubsystemHandlers() map[string]ssh.SubsystemHandler {
	m := make(map[string]ssh.SubsystemHandler, len(ssh.DefaultSubsystemHandlers))
	for k, v := range ssh.DefaultSubsystemHandlers {
		m[k] = v
	}
	return m
}

func (s *SSHServer) handleSession(sess ssh.Session) {
	ptyReq, winCh, isPty := sess.Pty()
	if !isPty {
		s.handleExec(sess)
		return
	}

	ptmx, err := pty.New()
	if err != nil {
		s.fail(sess, "allocate pty", err)
		return
	}
	defer ptmx.Close()

	path, args := s.command(sess)
	cmd := ptmx.Command(path, args...)
	cmd.Env = append(os.Environ(), "TERM="+ptyReq.Term)

	if err := cmd.Start(); err != nil {
		s.fail(sess, "start shell", err)
		return
	}

	// Set the initial size before the shell draws its first prompt, otherwise
	// it renders at the default 80x24 until the first resize.
	if w := ptyReq.Window; w.Width > 0 && w.Height > 0 {
		_ = ptmx.Resize(w.Width, w.Height)
	}
	go func() {
		for w := range winCh {
			_ = ptmx.Resize(w.Width, w.Height)
		}
	}()

	// Neither copy can be waited on directly.
	//
	// session->pty blocks reading input that may never come. pty->session
	// looks like it should end when the shell exits, and does on Unix -- but
	// the Windows ConPTY output handle never signals EOF, so that read hangs
	// forever and the session would never close.
	//
	// So: wait on the process, then give the output copy a short grace period
	// to drain what the shell wrote on its way out. The deferred ptmx.Close
	// unblocks it afterwards either way.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(sess, ptmx)
	}()
	go func() { _, _ = io.Copy(ptmx, sess) }()

	err = cmd.Wait()

	select {
	case <-drained:
	case <-time.After(drainGrace):
	}

	code := exitCode(err)
	s.log.Info("session ended", "user", sess.User(), "exit", code)
	_ = sess.Exit(code)
}

// handleExec serves a non-interactive request such as `ssh host -- ls`, where
// stdout and stderr stay separate and no terminal is involved.
func (s *SSHServer) handleExec(sess ssh.Session) {
	path, args := s.command(sess)
	if sess.RawCommand() == "" {
		io.WriteString(sess.Stderr(), "san_tunnels: no command given and no pty requested; use ssh -t for a shell\n")
		_ = sess.Exit(1)
		return
	}

	cmd := exec.Command(path, args...)
	cmd.Env = os.Environ()
	cmd.Stdout = sess
	cmd.Stderr = sess.Stderr()

	// Stdin must go through an explicit pipe.
	//
	// Assigning cmd.Stdin = sess makes os/exec run its own copy goroutine and
	// makes Wait() block until that goroutine finishes -- which it never does,
	// because it is reading a session whose client keeps stdin open for the
	// lifetime of the command. `ssh host ls` would hang forever after printing
	// its output. StdinPipe is closed by Wait once the process exits, so the
	// copy below cannot hold the command open.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		s.fail(sess, "open stdin pipe", err)
		return
	}
	go func() {
		defer stdin.Close()
		_, _ = io.Copy(stdin, sess)
	}()

	if err := cmd.Start(); err != nil {
		s.fail(sess, "start command", err)
		return
	}
	code := exitCode(cmd.Wait())
	s.log.Info("exec ended", "user", sess.User(), "command", sess.RawCommand(), "exit", code)
	_ = sess.Exit(code)
}

// command decides what to run: the login shell for an interactive session, or
// the shell wrapped around whatever the client asked for.
func (s *SSHServer) command(sess ssh.Session) (string, []string) {
	raw := sess.RawCommand()
	if raw == "" {
		return s.shell, nil
	}
	if runtime.GOOS == "windows" {
		return s.shell, []string{"/c", raw}
	}
	return s.shell, []string{"-c", raw}
}

func (s *SSHServer) fail(sess ssh.Session, what string, err error) {
	s.log.Error(what, "error", err)
	fmt.Fprintf(sess.Stderr(), "san_tunnels: %s: %v\n", what, err)
	_ = sess.Exit(1)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}

func defaultShell() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("COMSPEC"); p != "" {
			return p
		}
		return "cmd.exe"
	}
	if p := os.Getenv("SHELL"); p != "" {
		return p
	}
	return "/bin/sh"
}
