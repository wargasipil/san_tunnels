package wsconn

import (
	"context"
	"time"

	"github.com/coder/websocket"
)

const (
	// KeepaliveInterval is how often an idle tunnel is pinged.
	//
	// Middleboxes reap idle NAT and proxy entries aggressively, and 60s is a
	// common floor -- an SSH session left at a prompt over lunch is exactly
	// the shape of traffic they drop. Pinging well under that keeps the path
	// alive. The Connect transport gets this free from HTTP/2 pings; a
	// WebSocket has to do it by hand.
	KeepaliveInterval = 25 * time.Second

	// KeepaliveTimeout bounds how long a pong may take before the peer is
	// treated as gone.
	//
	// This is the half that matters for correctness rather than liveness. A
	// connection whose peer has vanished without a FIN -- a laptop that slept,
	// a NAT entry that expired mid-session -- looks identical to an idle one,
	// so reads block forever and the session wedges. An unanswered ping is the
	// only way to tell the difference.
	KeepaliveTimeout = 10 * time.Second
)

// Keepalive pings the peer until ctx is cancelled or the peer stops answering.
//
// It must run concurrently with a reader: coder/websocket processes the pong
// on the read path, so Ping on an unread connection would always time out.
// Every tunnel built here has a reader by construction.
//
// On failure it closes the connection rather than just returning. That is the
// point: a wedged tunnel has to surface as a read error so the io.Copy above
// it unblocks and the session actually ends, instead of hanging until someone
// types into it.
func Keepalive(ctx context.Context, c *websocket.Conn, interval, timeout time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pingCtx, cancel := context.WithTimeout(ctx, timeout)
			err := c.Ping(pingCtx)
			cancel()
			if err != nil {
				// CloseNow, not Close: the peer is unresponsive, so waiting
				// for a close handshake it will never complete just delays
				// unblocking the reader.
				_ = c.CloseNow()
				return
			}
		}
	}
}
