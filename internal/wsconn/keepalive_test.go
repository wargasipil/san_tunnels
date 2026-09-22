package wsconn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/wargasipil/san_tunnels/internal/wsconn"
)

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

// dialTo opens a client connection and keeps a reader running, which the
// library needs in order to process incoming pongs and answer incoming pings.
func dialTo(t *testing.T, ctx context.Context, url string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, wsURL(url), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

// The case that matters: a peer that has vanished without closing the socket.
// It looks exactly like an idle one, so reads block forever and the session
// wedges. An unanswered ping is the only way to tell them apart.
func TestKeepaliveClosesUnresponsivePeer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		// Deliberately never read, so pings are never answered.
		<-r.Context().Done()
		_ = c.CloseNow()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := dialTo(t, ctx, srv.URL)
	go wsconn.Keepalive(ctx, c, 50*time.Millisecond, 200*time.Millisecond)

	// Keepalive must close the connection, which is what unblocks the reader
	// above it. Without that the read below would hang until the test dies.
	read := make(chan error, 1)
	go func() {
		_, _, err := c.Read(ctx)
		read <- err
	}()

	select {
	case err := <-read:
		if err == nil {
			t.Fatal("read succeeded on a connection whose peer never answered a ping")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("keepalive did not close an unresponsive connection: a wedged tunnel would hang forever")
	}
}

// A quiet but healthy tunnel must survive many keepalive rounds. This is the
// half that keeps middleboxes from reaping an idle session.
func TestKeepaliveKeepsIdleConnectionAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow() //nolint:errcheck // test server
		// Reading is what lets the library answer pings.
		for {
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := dialTo(t, ctx, srv.URL)

	// The client needs a reader of its own to receive the pongs.
	readErr := make(chan error, 1)
	go func() {
		for {
			if _, _, err := c.Read(ctx); err != nil {
				readErr <- err
				return
			}
		}
	}()

	go wsconn.Keepalive(ctx, c, 50*time.Millisecond, 2*time.Second)

	// Long enough for several rounds to complete.
	select {
	case err := <-readErr:
		t.Fatalf("connection died while idle but healthy: %v", err)
	case <-time.After(600 * time.Millisecond):
	}

	if err := c.Write(ctx, websocket.MessageBinary, []byte("still alive")); err != nil {
		t.Fatalf("write after idle keepalive rounds: %v", err)
	}
}

// Cancelling the context must stop the goroutine, or every closed tunnel
// leaves one behind.
func TestKeepaliveStopsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow() //nolint:errcheck // test server
		for {
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	c := dialTo(t, ctx, srv.URL)

	stopped := make(chan struct{})
	go func() {
		wsconn.Keepalive(ctx, c, 50*time.Millisecond, time.Second)
		close(stopped)
	}()

	cancel()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive outlived its context")
	}
}
