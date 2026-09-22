// Package wsconn carries a tunnel over a WebSocket, as the same net.Conn the
// Connect transport produces.
//
// It exists because an HTTP/1.1 Upgrade survives intermediaries that a
// full-duplex HTTP/2 stream does not: nginx without grpc_pass, an ALB with an
// HTTP/1.1 target group, an ingress with no gRPC annotation. Those downgrade
// h2 and the tunnel hangs; they have forwarded WebSockets since 2011.
//
// Both halves of the wire convention live here so the client and the agent
// cannot drift apart:
//
//	binary message  payload bytes
//	text "close-write"  half-close, the FIN that WebSocket itself has no frame for
//	close frame  the connection is done in both directions
//
// The text frame is what buys parity with the Connect transport. WebSocket
// closes wholesale, so without it CloseWrite would be a silent no-op and a
// tunnelled TCP service that signals end-of-input by half-closing would hang
// waiting for bytes that never come.
package wsconn

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/coder/websocket"

	"github.com/wargasipil/san_tunnels/internal/streamconn"
)

const (
	// Path is where the agent accepts tunnel upgrades. The endpoint name
	// rides in the query string, so it is validated before the upgrade and a
	// bad name is an HTTP error rather than a socket that closes immediately.
	Path = "/ws"
	// PingPath is the duplex probe, the WebSocket counterpart of the Ping RPC.
	PingPath = "/ws/ping"

	// EndpointParam names the allowlisted endpoint to open.
	EndpointParam = "endpoint"

	// closeWrite is the half-close control message. It is a text frame
	// precisely so it cannot collide with payload, which is always binary.
	closeWrite = "close-write"

	// ReadLimit caps one message. The default is 32KiB, which io.Copy's 32KB
	// buffer sits exactly on top of -- close enough to the edge to be worth
	// moving away from.
	ReadLimit = 1 << 20
)

// New adapts an established WebSocket to a net.Conn.
//
// ctx bounds the whole connection: cancelling it fails the reads and writes
// in flight, which is how a cancelled ProxyCommand tears the tunnel down
// rather than orphaning it.
func New(ctx context.Context, c *websocket.Conn, local, remote string) *streamconn.Conn {
	c.SetReadLimit(ReadLimit)

	// Cancelled on Close so the keepalive goroutine cannot outlive the tunnel.
	ctx, cancel := context.WithCancel(ctx)
	go Keepalive(ctx, c, KeepaliveInterval, KeepaliveTimeout)

	var once sync.Once
	return streamconn.New(streamconn.Options{
		Recv: func() ([]byte, error) {
			for {
				typ, b, err := c.Read(ctx)
				if err != nil {
					return nil, normalizeClose(err)
				}
				if typ == websocket.MessageBinary {
					return b, nil
				}
				if string(b) == closeWrite {
					// The peer is done sending. io.EOF is what every reader
					// above this expects from a half-closed connection.
					return nil, io.EOF
				}
				return nil, fmt.Errorf("unexpected websocket text message %q", b)
			}
		},
		Send: func(b []byte) error {
			return c.Write(ctx, websocket.MessageBinary, b)
		},
		CloseSend: func() error {
			// Idempotent: Proxy half-closes and then closes, and a second
			// control frame on a closed socket would surface as a spurious
			// error from Close.
			var err error
			once.Do(func() {
				err = c.Write(ctx, websocket.MessageText, []byte(closeWrite))
			})
			return err
		},
		Close: func() error {
			cancel()
			return c.Close(websocket.StatusNormalClosure, "")
		},
		Local:  local,
		Remote: remote,
	})
}

// NewServer adapts the agent's side, where there is no half-close to send.
//
// The handler returning is what ends the connection, exactly as the Connect
// handler's return ends the response stream, so the agent never writes a
// close-write frame of its own.
func NewServer(ctx context.Context, c *websocket.Conn, remote string) *streamconn.Conn {
	c.SetReadLimit(ReadLimit)

	// The agent pings too, rather than relying on the client to. A tunnel can
	// be reaped from either end, and the side that notices first is whichever
	// one's path broke.
	ctx, cancel := context.WithCancel(ctx)
	go Keepalive(ctx, c, KeepaliveInterval, KeepaliveTimeout)

	return streamconn.New(streamconn.Options{
		Recv: func() ([]byte, error) {
			typ, b, err := c.Read(ctx)
			if err != nil {
				return nil, normalizeClose(err)
			}
			if typ == websocket.MessageBinary {
				return b, nil
			}
			if string(b) == closeWrite {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("unexpected websocket text message %q", b)
		},
		Send: func(b []byte) error {
			return c.Write(ctx, websocket.MessageBinary, b)
		},
		Close: func() error {
			cancel()
			return nil
		},
		Local:  "agent",
		Remote: remote,
	})
}

// normalizeClose turns an orderly WebSocket shutdown into io.EOF.
//
// A peer that closes cleanly is not an error to anything reading above this,
// and without the translation every finished session logs a failure.
func normalizeClose(err error) error {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return io.EOF
	}
	return err
}
