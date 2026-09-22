package agent

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/coder/websocket"

	"github.com/wargasipil/san_tunnels/internal/wsconn"
)

// WSOptions configures the WebSocket door.
type WSOptions struct {
	Service *Service
	// Origins are the browser origins allowed to upgrade. Empty means
	// same-origin only, which is what a Go client (sending no Origin header)
	// gets anyway; it matters the moment a page in a browser dials the agent.
	Origins []string
	Log     *slog.Logger
}

// wsHandler serves tunnel upgrades at wsconn.Path.
//
// The endpoint name is validated before the upgrade so a bad one is an
// ordinary 404 with a readable body. After the upgrade there is no status
// code left to send, only a close frame, and a client that sees a socket open
// and instantly shut has nothing to report.
func wsHandler(o WSOptions) http.Handler {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint := r.URL.Query().Get(wsconn.EndpointParam)
		if endpoint == "" {
			endpoint = ShellEndpoint
		}
		if _, err := o.Service.Resolve(endpoint); err != nil {
			log.Warn("websocket upgrade refused", "endpoint", endpoint, "remote", r.RemoteAddr, "err", err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: o.Origins,
		})
		if err != nil {
			// Accept has already written the response.
			log.Warn("websocket upgrade failed", "remote", r.RemoteAddr, "err", err)
			return
		}
		defer c.CloseNow() //nolint:errcheck // best effort once the session is over

		// The 101 is the acknowledgement, so there is nothing for Handle to
		// send: the endpoint was proven good before the upgrade.
		conn := wsconn.NewServer(r.Context(), c, r.RemoteAddr)
		if err := o.Service.Handle(r.Context(), endpoint, conn, nil); err != nil {
			log.Warn("websocket tunnel ended", "endpoint", endpoint, "remote", r.RemoteAddr, "err", err)
			c.Close(websocket.StatusInternalError, "tunnel failed") //nolint:errcheck // best effort
			return
		}
		c.Close(websocket.StatusNormalClosure, "") //nolint:errcheck // best effort
	})
}

// wsPingHandler echoes binary frames, the WebSocket counterpart of the Ping
// RPC.
//
// It proves less than its HTTP/2 sibling does, and deliberately so: a
// WebSocket is full-duplex by construction, so there is no half-duplex path
// for it to catch. What it still checks is everything else the probe is used
// for -- that the agent is reachable, that the upgrade survives whatever is
// in between, and that the bearer token is accepted.
func wsPingHandler(o WSOptions) http.Handler {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: o.Origins,
		})
		if err != nil {
			log.Warn("websocket ping upgrade failed", "remote", r.RemoteAddr, "err", err)
			return
		}
		defer c.CloseNow() //nolint:errcheck // best effort

		c.SetReadLimit(wsconn.ReadLimit)
		for {
			typ, b, err := c.Read(r.Context())
			if err != nil {
				if isOrderlyClose(err) {
					c.Close(websocket.StatusNormalClosure, "") //nolint:errcheck // best effort
				}
				return
			}
			if err := c.Write(r.Context(), typ, b); err != nil {
				return
			}
		}
	})
}

func isOrderlyClose(err error) bool {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	}
	return errors.Is(err, http.ErrBodyNotAllowed)
}
