// Package client is the entry-point side: it opens tunnel streams and exposes
// them as ordinary connections, so the real ssh client can ride on top.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	v1 "github.com/wargasipil/san_tunnels/gen/san/tunnels/v1"
	"github.com/wargasipil/san_tunnels/gen/san/tunnels/v1/tunnelsv1connect"
	"github.com/wargasipil/san_tunnels/internal/streamconn"
)

// Transport selects the wire beneath the tunnel.
//
// There are two, and they are not peers: Connect over HTTP/2 is the default
// and the one that supports every feature, WebSocket is the fallback for
// paths that mangle full-duplex h2. Choosing is explicit rather than
// automatic on purpose -- silently retrying over WebSocket when h2 fails
// would hide exactly the misconfiguration that Check and the agent's
// HTTP/2 assertion exist to make loud.
type Transport string

const (
	// TransportConnect is Connect RPC over HTTP/2. The default.
	TransportConnect Transport = "connect"
	// TransportWS is a WebSocket over HTTP/1.1.
	TransportWS Transport = "ws"
)

// ParseTransport validates a configured transport name. Empty means the default.
func ParseTransport(s string) (Transport, error) {
	switch Transport(s) {
	case "", TransportConnect:
		return TransportConnect, nil
	case TransportWS:
		return TransportWS, nil
	default:
		return "", fmt.Errorf("unknown transport %q: want %q or %q", s, TransportConnect, TransportWS)
	}
}

// Target is a resolved agent: what a name in the client config points at.
type Target struct {
	Name      string
	URL       string
	Token     string
	User      string
	Insecure  bool
	Transport Transport
}

// Conn is one tunnelled connection.
//
// CloseWrite is named separately from net.Conn because half-close is the one
// thing the two transports have to work at agreeing on: Connect gets it free
// from CloseRequest, WebSocket has no such frame and needs the control
// message in package wsconn.
type Conn interface {
	net.Conn
	CloseWrite() error
}

// httpClient returns a transport that is explicitly HTTP/2.
//
// http.DefaultTransport is deliberately not used: it negotiates HTTP/2 only
// over TLS with ALPN and silently falls back to HTTP/1.1, which cannot carry a
// full-duplex stream. Choosing http2.Transport makes the requirement a
// decision rather than a negotiation nobody watched.
func httpClient(t Target) (*http.Client, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, fmt.Errorf("parse server url %q: %w", t.URL, err)
	}

	switch u.Scheme {
	case "https":
		return &http.Client{Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: t.Insecure}, //nolint:gosec // opt-in, dev only
		}}, nil
	case "http":
		// h2c: prior-knowledge HTTP/2 over cleartext, no upgrade dance.
		return &http.Client{Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}}, nil
	default:
		return nil, fmt.Errorf("server url %q must be http or https", t.URL)
	}
}

func newService(t Target) (tunnelsv1connect.TunnelServiceClient, error) {
	hc, err := httpClient(t)
	if err != nil {
		return nil, err
	}
	return tunnelsv1connect.NewTunnelServiceClient(hc, t.URL,
		connect.WithInterceptors(bearer{token: t.Token})), nil
}

// Open dials the agent and returns the tunnel as a net.Conn, after the agent
// has confirmed the endpoint is open.
func Open(ctx context.Context, t Target, endpoint string) (Conn, error) {
	switch t.Transport {
	case TransportWS:
		return openWS(ctx, t, endpoint)
	default:
		return openConnect(ctx, t, endpoint)
	}
}

// openConnect starts a Forward stream over Connect/HTTP2.
func openConnect(ctx context.Context, t Target, endpoint string) (Conn, error) {
	svc, err := newService(t)
	if err != nil {
		return nil, err
	}

	stream := svc.Forward(ctx)
	if err := stream.Send(&v1.ForwardRequest{
		Payload: &v1.ForwardRequest_Open{Open: &v1.Open{Endpoint: endpoint}},
	}); err != nil {
		return nil, fmt.Errorf("open endpoint %q on %s: %w", endpoint, t.URL, err)
	}

	// Wait for Opened before handing the stream over, so a refused endpoint
	// surfaces as an error here rather than as an unexplained EOF later.
	resp, err := stream.Receive()
	if err != nil {
		return nil, fmt.Errorf("open endpoint %q on %s: %w", endpoint, t.URL, err)
	}
	if resp.GetOpened() == nil {
		return nil, errors.New("agent did not acknowledge the open request")
	}

	return clientConn(stream, t), nil
}

func clientConn(stream *connect.BidiStreamForClient[v1.ForwardRequest, v1.ForwardResponse], t Target) *streamconn.Conn {
	return streamconn.New(streamconn.Options{
		Recv: func() ([]byte, error) {
			m, err := stream.Receive()
			if err != nil {
				return nil, err
			}
			return m.GetData(), nil
		},
		Send: func(b []byte) error {
			return stream.Send(&v1.ForwardRequest{
				Payload: &v1.ForwardRequest_Data{Data: b},
			})
		},
		// CloseRequest half-closes our side; the agent's Receive then returns
		// io.EOF, which is how a one-way FIN crosses the tunnel.
		CloseSend: stream.CloseRequest,
		Local:     "client",
		Remote:    t.Name,
	})
}

// bearer attaches the transport token to every call, streaming included.
type bearer struct{ token string }

func (b bearer) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if b.token != "" {
			req.Header().Set("Authorization", "Bearer "+b.token)
		}
		return next(ctx, req)
	}
}

func (b bearer) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		if b.token != "" {
			conn.RequestHeader().Set("Authorization", "Bearer "+b.token)
		}
		return conn
	}
}

func (b bearer) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
