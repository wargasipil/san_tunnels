package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	v1 "github.com/wargasipil/san_tunnels/gen/san/tunnels/v1"
)

// Proxy bridges in/out to a tunnel stream. Run as an ssh ProxyCommand, `in`
// and `out` are this process's stdin and stdout, and every byte on them is SSH
// wire traffic.
//
// Nothing else may write to `out`. A stray log line lands in the middle of the
// SSH handshake and ssh reports something unhelpful about a bad packet length,
// with nothing pointing at the real cause -- which is why the CLI sends all
// logging and all urfave output to stderr.
func Proxy(ctx context.Context, t Target, endpoint string, in io.Reader, out io.Writer) error {
	conn, err := Open(ctx, t, endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Upstream runs in the background: it blocks reading stdin until the ssh
	// client goes away, so it must not gate our return.
	go func() {
		_, _ = io.Copy(conn, in)
		_ = conn.CloseWrite()
	}()

	_, err = io.Copy(out, conn)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("tunnel to %s closed: %w", t.Name, err)
	}
	return nil
}

// Check proves the path is usable, and over Connect that it is full-duplex.
//
// It sends, reads the reply, then sends again while the request body is still
// open. A path that downgrades to HTTP/1.1 anywhere cannot do this: the
// intermediary buffers the whole request before forwarding it, so the first
// reply never arrives and this times out instead of hanging forever in a real
// session.
//
// Over WebSocket the same round trip proves less, because a WebSocket is
// duplex by construction. See checkWS.
func Check(ctx context.Context, t Target, timeout time.Duration) error {
	if t.Transport == TransportWS {
		return checkWS(ctx, t, timeout)
	}
	svc, err := newService(t)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stream := svc.Ping(ctx)
	defer func() { _ = stream.CloseRequest() }()

	const rounds = 2
	for i := uint64(1); i <= rounds; i++ {
		if err := stream.Send(&v1.PingRequest{Seq: i}); err != nil {
			return fmt.Errorf("ping %d to %s: %w", i, t.URL, err)
		}
		resp, err := stream.Receive()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// Name the remedy, not just the cause. Falling back to
				// WebSocket automatically is deliberately not done -- this
				// failure is a hang rather than an error, so detecting it
				// costs a timeout on every connection, and routing around it
				// silently leaves the broken proxy broken for everything
				// else behind it. Telling the operator is the whole point.
				return fmt.Errorf(
					"no reply from %s within %s on round %d of the duplex probe. "+
						"The connection was established, so this is usually a proxy in the path "+
						"that speaks HTTP/2 to you and HTTP/1.1 to the agent: it buffers the whole "+
						"request before forwarding, so full-duplex streams never work.\n"+
						"Fix the path if you can (nginx grpc_pass, an ALB target group with protocol "+
						"version HTTP2 or gRPC, backend-protocol: GRPC on an ingress, or an L4 "+
						"passthrough such as an NLB).\n"+
						"If you cannot, this agent can use a WebSocket instead: retry with "+
						"--transport ws, and set \"transport\": \"ws\" on %q in the client config "+
						"to make it stick", t.URL, timeout, i, t.Name)
			}
			return fmt.Errorf("ping %d to %s: %w", i, t.URL, err)
		}
		if resp.GetSeq() != i {
			return fmt.Errorf("ping %d to %s: agent replied with seq %d", i, t.URL, resp.GetSeq())
		}
	}
	return nil
}
