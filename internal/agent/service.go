package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/wargasipil/san_tunnels/gen/san/tunnels/v1"
	"github.com/wargasipil/san_tunnels/internal/streamconn"
)

// ShellEndpoint is the reserved endpoint name routed to the embedded SSH
// server. It is handled in-process: no socket is opened and nothing listens.
const ShellEndpoint = "shell"

// dialTimeout bounds how long a tunnelled TCP endpoint may take to connect.
const dialTimeout = 10 * time.Second

// Service implements the TunnelService handlers.
type Service struct {
	ssh       *SSHServer
	endpoints map[string]string
	log       *slog.Logger
}

// NewService builds the handler. endpoints maps allowlisted names to TCP
// addresses; the name "shell" is reserved.
func NewService(sshServer *SSHServer, endpoints map[string]string, log *slog.Logger) (*Service, error) {
	if sshServer == nil {
		return nil, errors.New("an ssh server is required")
	}
	if _, ok := endpoints[ShellEndpoint]; ok {
		return nil, fmt.Errorf("endpoint %q is reserved for the embedded ssh server", ShellEndpoint)
	}
	if log == nil {
		log = slog.Default()
	}
	cp := make(map[string]string, len(endpoints))
	for k, v := range endpoints {
		cp[k] = v
	}
	return &Service{ssh: sshServer, endpoints: cp, log: log}, nil
}

// Endpoints lists the allowlisted names, "shell" included.
func (s *Service) Endpoints() map[string]string {
	out := map[string]string{ShellEndpoint: "embedded ssh server (in-process)"}
	for k, v := range s.endpoints {
		out[k] = v
	}
	return out
}

// Resolve checks a name against the allowlist, returning the TCP address it
// dials. The empty string means the reserved in-process shell.
//
// It is separate from Handle so a transport can reject a bad name before it
// commits to anything: the WebSocket path calls it before upgrading, which
// turns an unknown endpoint into a 404 instead of a socket that opens and
// then immediately shuts for reasons the client cannot see.
func (s *Service) Resolve(name string) (string, error) {
	if name == ShellEndpoint {
		return "", nil
	}
	addr, ok := s.endpoints[name]
	if !ok {
		return "", fmt.Errorf("endpoint %q is not in the allowlist", name)
	}
	return addr, nil
}

// Handle routes one open tunnel connection to its endpoint.
//
// This is the transport-free half of the agent: everything above it
// (Connect over HTTP/2, WebSocket over HTTP/1.1) exists only to produce a
// net.Conn and a name, and nothing below it knows which one it got.
//
// ack, if given, confirms the endpoint to the client. It runs after the name
// is known good and any upstream dial has succeeded, but before a byte of
// payload moves, so a refused endpoint surfaces as an error rather than as an
// unexplained EOF later. The Connect transport sends its `Opened` message
// there; the WebSocket transport has already sent its 101 and passes nil.
func (s *Service) Handle(ctx context.Context, endpoint string, conn net.Conn, ack func() error) error {
	addr, err := s.Resolve(endpoint)
	if err != nil {
		return connect.NewError(connect.CodeNotFound, err)
	}
	if addr == "" {
		return s.handleShell(conn, ack)
	}
	return s.handleTCP(ctx, conn, ack, endpoint, addr)
}

// handleShell hands the connection straight to the embedded SSH server. This
// is the whole trick: ssh.Server takes a net.Conn, so no port is ever bound.
func (s *Service) handleShell(conn net.Conn, ack func() error) error {
	if ack != nil {
		if err := ack(); err != nil {
			return err
		}
	}
	peer := conn.RemoteAddr().String()
	s.log.Info("tunnel opened", "endpoint", ShellEndpoint, "peer", peer)
	s.ssh.HandleConn(conn)
	s.log.Info("tunnel closed", "endpoint", ShellEndpoint, "peer", peer)
	return nil
}

// handleTCP splices the connection onto an allowlisted local address.
func (s *Service) handleTCP(ctx context.Context, conn net.Conn, ack func() error, name, addr string) error {
	d := net.Dialer{Timeout: dialTimeout}
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable,
			fmt.Errorf("dial endpoint %q at %s: %w", name, addr, err))
	}
	defer tcp.Close()

	if ack != nil {
		if err := ack(); err != nil {
			return err
		}
	}
	s.log.Info("tunnel opened", "endpoint", name, "addr", addr, "peer", conn.RemoteAddr())

	// Upstream copy runs in the background. When the client half-closes, the
	// FIN is propagated so the far side sees a clean end of input rather than
	// waiting on a connection that will never send again.
	go func() {
		_, _ = io.Copy(tcp, conn)
		if t, ok := tcp.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
	}()

	// Returning ends the stream, and the deferred Close unblocks the
	// goroutine above.
	_, _ = io.Copy(conn, tcp)
	s.log.Info("tunnel closed", "endpoint", name, "addr", addr)
	return nil
}

// Forward carries one tunnelled connection over Connect.
func (s *Service) Forward(ctx context.Context, stream *connect.BidiStream[v1.ForwardRequest, v1.ForwardResponse]) error {
	first, err := stream.Receive()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New("the first message on a Forward stream must be `open`"))
	}

	return s.Handle(ctx, open.GetEndpoint(), serverConn(stream), func() error {
		return sendOpened(stream)
	})
}

// Ping echoes sequence numbers. It exists to prove the path is full-duplex:
// the client sends, reads a reply, then sends again, which a half-duplex path
// cannot complete.
func (s *Service) Ping(ctx context.Context, stream *connect.BidiStream[v1.PingRequest, v1.PingResponse]) error {
	for {
		req, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.Send(&v1.PingResponse{Seq: req.GetSeq()}); err != nil {
			return err
		}
	}
}

func sendOpened(stream *connect.BidiStream[v1.ForwardRequest, v1.ForwardResponse]) error {
	return stream.Send(&v1.ForwardResponse{
		Payload: &v1.ForwardResponse_Opened{Opened: &v1.Opened{}},
	})
}

// serverConn lifts the agent side of a Forward stream to a net.Conn.
//
// There is no CloseSend: on the server the response stream ends when the
// handler returns, which is exactly the half-close we want.
func serverConn(stream *connect.BidiStream[v1.ForwardRequest, v1.ForwardResponse]) *streamconn.Conn {
	return streamconn.New(streamconn.Options{
		Recv: func() ([]byte, error) {
			m, err := stream.Receive()
			if err != nil {
				return nil, err
			}
			if m.GetOpen() != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument,
					errors.New("received a second `open` on an established stream"))
			}
			return m.GetData(), nil
		},
		Send: func(b []byte) error {
			return stream.Send(&v1.ForwardResponse{
				Payload: &v1.ForwardResponse_Data{Data: b},
			})
		},
		Local:  "agent",
		Remote: stream.Peer().Addr,
	})
}
