package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/wargasipil/san_tunnels/internal/wsconn"
)

// wsHTTPClient returns a transport that is explicitly HTTP/1.1.
//
// The mirror image of httpClient, and for the same reason: an Upgrade
// handshake cannot travel over HTTP/2 without RFC 8441 extended CONNECT,
// which Go's server does not implement. ForceAttemptHTTP2 stays off so ALPN
// cannot quietly negotiate h2 and break the upgrade.
func wsHTTPClient(t Target) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: t.Insecure, //nolint:gosec // opt-in, dev only
				NextProtos:         []string{"http/1.1"},
			},
		},
	}
}

// wsURL rewrites the agent URL for a WebSocket path.
//
// The config holds one URL per agent whichever transport is in use, so http
// and https are accepted and mapped rather than demanding the user keep a
// second ws:// URL in step with the first.
func wsURL(rawURL, path string, query url.Values) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse server url %q: %w", rawURL, err)
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("server url %q must be http, https, ws or wss", rawURL)
	}
	u.Path = path
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// dialWS performs the upgrade, with the bearer token in a header.
//
// A browser cannot set headers on a WebSocket, which is why a browser client
// will need a different credential path (a short-lived ticket, most likely).
// A Go client has no such limit, so it uses the same Authorization header the
// Connect transport does and is checked by the same middleware.
func dialWS(ctx context.Context, t Target, path string, query url.Values) (*websocket.Conn, error) {
	target, err := wsURL(t.URL, path, query)
	if err != nil {
		return nil, err
	}

	header := http.Header{}
	if t.Token != "" {
		header.Set("Authorization", "Bearer "+t.Token)
	}

	c, resp, err := websocket.Dial(ctx, target, &websocket.DialOptions{
		HTTPClient: wsHTTPClient(t),
		HTTPHeader: header,
	})
	if err != nil {
		// websocket.Dial reports only the status code, which would make an
		// unknown endpoint read as a bare 404 while the Connect transport
		// names the allowlist. The agent's reason is in the body, which Dial
		// preserves for exactly this, so the two doors fail alike.
		if reason := handshakeReason(resp); reason != "" {
			return nil, fmt.Errorf("websocket to %s: %s", target, reason)
		}
		return nil, fmt.Errorf("websocket to %s: %w", target, err)
	}
	return c, nil
}

// handshakeReason extracts what the agent said about a refused upgrade.
func handshakeReason(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck // diagnostics only
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if msg := strings.TrimSpace(string(b)); msg != "" {
		return fmt.Sprintf("%s: %s", resp.Status, msg)
	}
	return resp.Status
}

// openWS opens a tunnel over a WebSocket.
//
// There is no Opened message to wait for: the endpoint is validated before
// the upgrade, so the 101 response is itself the acknowledgement.
func openWS(ctx context.Context, t Target, endpoint string) (Conn, error) {
	c, err := dialWS(ctx, t, wsconn.Path, url.Values{wsconn.EndpointParam: {endpoint}})
	if err != nil {
		return nil, fmt.Errorf("open endpoint %q on %s: %w", endpoint, t.URL, err)
	}
	return wsconn.New(ctx, c, "client", t.Name), nil
}

// checkWS is the WebSocket half of Check.
//
// It sends, reads the reply, then sends again, the same shape as the Ping
// RPC, but it proves less and says so: a WebSocket is full-duplex by
// construction, so there is no half-duplex path for the round trip to catch.
// What it does establish is that the agent is reachable, that the upgrade
// survives whatever sits in between, and that the token is accepted.
func checkWS(ctx context.Context, t Target, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c, err := dialWS(ctx, t, wsconn.PingPath, nil)
	if err != nil {
		return err
	}
	defer c.CloseNow() //nolint:errcheck // best effort

	for seq := byte(1); seq <= 2; seq++ {
		if err := c.Write(ctx, websocket.MessageBinary, []byte{seq}); err != nil {
			return fmt.Errorf("websocket probe to %s: send %d: %w", t.Name, seq, err)
		}
		_, b, err := c.Read(ctx)
		if err != nil {
			return fmt.Errorf("websocket probe to %s: receive %d: %w", t.Name, seq, err)
		}
		if len(b) != 1 || b[0] != seq {
			return errors.New("websocket probe returned the wrong payload")
		}
	}
	return c.Close(websocket.StatusNormalClosure, "")
}
