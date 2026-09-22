// Package streamconn adapts a Connect bidirectional stream to net.Conn.
//
// This is what lets the embedded SSH server run without listening on anything:
// ssh.Server accepts a net.Conn, so the tunnel stream is handed to it directly
// rather than through a loopback socket.
package streamconn

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Addr is the placeholder address reported by Conn. A tunnelled stream has no
// meaningful network address of its own; the transport below it does.
type Addr struct{ name string }

func (a Addr) Network() string { return "san_tunnels" }
func (a Addr) String() string  { return a.name }

// Conn is a net.Conn backed by a pair of stream callbacks.
//
// Deadlines are accepted and ignored. The underlying Connect stream has no
// per-read timeout to set, so anything needing idle handling must implement it
// above this type; returning an error instead would break libraries that set a
// deadline defensively.
type Conn struct {
	recv      func() ([]byte, error)
	send      func([]byte) error
	closeSend func() error
	closeAll  func() error

	local  Addr
	remote Addr

	readMu  sync.Mutex
	rest    []byte
	readErr error

	writeMu  sync.Mutex
	writeErr error

	closeOnce sync.Once
}

// Options carries the stream plumbing for New.
type Options struct {
	// Recv returns the next chunk of payload bytes, or an error. io.EOF means
	// the peer closed its sending side.
	Recv func() ([]byte, error)
	// Send writes one chunk of payload bytes.
	Send func([]byte) error
	// CloseSend half-closes our sending direction. Optional.
	CloseSend func() error
	// Close releases the transport underneath. Optional, and empty for the
	// Connect transport: ending the stream is all there is to do. A
	// WebSocket owns a real socket, so it passes one.
	Close func() error
	// Local and Remote name the endpoints, for logs only.
	Local, Remote string
}

// New builds a Conn from stream callbacks.
func New(o Options) *Conn {
	return &Conn{
		recv:      o.Recv,
		send:      o.Send,
		closeSend: o.CloseSend,
		closeAll:  o.Close,
		local:     Addr{name: o.Local},
		remote:    Addr{name: o.Remote},
	}
}

// Read fills p from the stream, buffering whatever a chunk does not satisfy.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.rest) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		b, err := c.recv()
		if err != nil {
			c.readErr = normalize(err)
			return 0, c.readErr
		}
		c.rest = b
	}

	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

// Write sends p as one chunk.
//
// p is copied because callers reuse their buffers -- io.Copy hands the same
// 32KB slice to every Write -- and we do not control whether the stream's
// marshaller retains what it is given.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		return 0, nil
	}

	b := make([]byte, len(p))
	copy(b, p)
	if err := c.send(b); err != nil {
		c.writeErr = normalize(err)
		return 0, c.writeErr
	}
	return len(p), nil
}

// CloseWrite half-closes the sending direction, which is how a tunnelled TCP
// connection propagates FIN in one direction while still reading the other.
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closeSend == nil {
		return nil
	}
	return c.closeSend()
}

// Close shuts the sending side, releases the transport and marks the conn
// unusable.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.closeSend != nil {
			err = c.closeSend()
		}
		if c.closeAll != nil {
			// Release the transport even when the half-close failed, or the
			// socket leaks. The first error is the informative one.
			if cerr := c.closeAll(); err == nil {
				err = cerr
			}
		}
		c.writeMu.Lock()
		if c.writeErr == nil {
			c.writeErr = net.ErrClosed
		}
		c.writeMu.Unlock()
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// normalize collapses the several ways a closed stream reports itself into
// io.EOF, so callers can use the usual idiom.
func normalize(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return err
}

var _ net.Conn = (*Conn)(nil)
