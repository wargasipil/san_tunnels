package streamconn

import (
	"errors"
	"io"
	"testing"
)

// chunks builds a Recv that hands back the given chunks, then io.EOF.
func chunks(bs ...[]byte) func() ([]byte, error) {
	i := 0
	return func() ([]byte, error) {
		if i >= len(bs) {
			return nil, io.EOF
		}
		b := bs[i]
		i++
		return b, nil
	}
}

func TestReadSpansChunks(t *testing.T) {
	c := New(Options{
		Recv: chunks([]byte("hello "), []byte("world")),
		Send: func([]byte) error { return nil },
	})

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
}

func TestReadSplitsOneChunkAcrossCalls(t *testing.T) {
	c := New(Options{
		Recv: chunks([]byte("abcdef")),
		Send: func([]byte) error { return nil },
	})

	buf := make([]byte, 2)
	var out []byte
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if string(out) != "abcdef" {
		t.Fatalf("got %q, want %q", out, "abcdef")
	}
}

// An empty chunk is legal on the wire and must not be mistaken for EOF.
func TestReadSkipsEmptyChunks(t *testing.T) {
	c := New(Options{
		Recv: chunks([]byte{}, []byte{}, []byte("x")),
		Send: func([]byte) error { return nil },
	})

	buf := make([]byte, 4)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "x" {
		t.Fatalf("got %q, want %q", buf[:n], "x")
	}
}

// io.Copy reuses one buffer for every Write, so a Conn that forwarded the
// caller's slice without copying would corrupt the stream.
func TestWriteCopiesCallerBuffer(t *testing.T) {
	var sent [][]byte
	c := New(Options{
		Recv: chunks(),
		Send: func(b []byte) error {
			sent = append(sent, b)
			return nil
		},
	})

	buf := []byte("first")
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	copy(buf, "SECON")

	if len(sent) != 1 {
		t.Fatalf("got %d sends, want 1", len(sent))
	}
	if string(sent[0]) != "first" {
		t.Fatalf("retained slice was mutated: got %q, want %q", sent[0], "first")
	}
}

func TestReadSurfacesErrorAndStaysFailed(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	c := New(Options{
		Recv: func() ([]byte, error) {
			calls++
			return nil, boom
		},
		Send: func([]byte) error { return nil },
	})

	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, boom) {
		t.Fatalf("first Read: got %v, want boom", err)
	}
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, boom) {
		t.Fatalf("second Read: got %v, want boom", err)
	}
	if calls != 1 {
		t.Fatalf("Recv called %d times, want 1: the error should be latched", calls)
	}
}

func TestCloseWriteHalfCloses(t *testing.T) {
	closed := 0
	c := New(Options{
		Recv:      chunks([]byte("still readable")),
		Send:      func([]byte) error { return nil },
		CloseSend: func() error { closed++; return nil },
	})

	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if closed != 1 {
		t.Fatalf("CloseSend called %d times, want 1", closed)
	}

	// Half-close must leave the read direction working.
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("ReadAll after CloseWrite: %v", err)
	}
	if string(got) != "still readable" {
		t.Fatalf("got %q", got)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	closed := 0
	c := New(Options{
		Recv:      chunks(),
		Send:      func([]byte) error { return nil },
		CloseSend: func() error { closed++; return nil },
	})

	_ = c.Close()
	_ = c.Close()
	if closed != 1 {
		t.Fatalf("CloseSend called %d times, want 1", closed)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close: want an error")
	}
}
