package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
)

// DefaultListen is the address `connect` binds when none is given.
//
// Loopback, and port 0 so the kernel picks a free one: binding a fixed port
// invites collisions between two agents, and binding anything but loopback
// would turn the entry host into an unauthenticated gateway to the target for
// everything else on the network.
const DefaultListen = "127.0.0.1:0"

// HostSuffix namespaces an agent's local name.
//
// ICANN reserved .internal for private use in 2024, so it can never be
// delegated out from under us -- unlike an invented TLD, which is only safe
// until it is not: .dev and .zip were both exactly this bet, and .dev
// arriving with enforced HSTS broke a great many local setups overnight. The
// `tunnels` label keeps us out of the way of anything else using .internal.
//
// .localhost would resolve for free under systemd-resolved, but not on
// Windows or macOS, which special-case only the bare name. Since two of three
// platforms need a hosts entry regardless, behaving the same everywhere is
// worth more than the partial freebie.
const HostSuffix = ".tunnels.internal"

// HostAlias is the name an agent is known by locally: "box-01.tunnels.internal".
//
// It is used two ways, and works in the first without resolving anywhere:
//
//   - as ssh's HostKeyAlias, which is pure bookkeeping -- ssh records the host
//     key under this name instead of under localhost, so every agent gets its
//     own known_hosts entry however the port moves. Needs no DNS at all.
//   - as a real hostname, once someone adds the hosts entries `client hosts`
//     prints. That is what GUI clients need, having no HostKeyAlias of their
//     own.
func HostAlias(name string) string {
	var b strings.Builder
	b.Grow(len(name) + len(HostSuffix))
	for _, r := range strings.ToLower(strings.TrimSuffix(name, HostSuffix)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			// Agent names are free-form; DNS labels are not.
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "agent" + HostSuffix
	}
	return b.String() + HostSuffix
}

// Listen accepts local TCP connections and gives each one its own tunnel.
//
// It is the counterpart to Proxy, for everything that cannot run an ssh
// ProxyCommand: database clients, GUI SSH clients, and any tool that only
// knows how to reach a host and a port. An allowlisted TCP endpoint has no
// other usable client path at all -- `proxy` writes the stream to stdout,
// which psql cannot be pointed at.
//
// ready is called once with the bound address, after the listener is up and
// before the first accept, so a caller can print connection instructions that
// name the real port.
func Listen(ctx context.Context, t Target, endpoint, addr string, ready func(net.Addr), log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if addr == "" {
		addr = DefaultListen
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer ln.Close() //nolint:errcheck // closing on the way out

	if ready != nil {
		ready(ln.Addr())
	}

	// Close the listener on cancellation so Accept returns instead of
	// blocking a Ctrl-C forever.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // cancelled, not a failure
			}
			return fmt.Errorf("accept on %s: %w", ln.Addr(), err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer local.Close() //nolint:errcheck // best effort

			// One tunnel per local connection, matching the
			// one-call-per-connection model on the wire.
			tunnel, err := Open(ctx, t, endpoint)
			if err != nil {
				// The local client is already connected, so there is no
				// status code to fail with -- say why here and drop it.
				log.Error("could not open tunnel for local connection",
					"agent", t.Name, "endpoint", endpoint,
					"local", local.RemoteAddr(), "err", err)
				return
			}
			defer tunnel.Close() //nolint:errcheck // best effort

			log.Info("connection opened", "agent", t.Name, "endpoint", endpoint, "local", local.RemoteAddr())
			splice(local, tunnel)
			log.Info("connection closed", "agent", t.Name, "endpoint", endpoint, "local", local.RemoteAddr())
		}()
	}
}

// splice copies in both directions, carrying half-close each way.
//
// The half-close matters for the TCP endpoints: a client that signals
// end-of-input by shutting its write side and then waits for a reply hangs
// forever if that shutdown is swallowed here.
func splice(local net.Conn, tunnel Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(tunnel, local)
		_ = tunnel.CloseWrite()
	}()

	_, err := io.Copy(local, tunnel)
	if err == nil || errors.Is(err, io.EOF) {
		if tc, ok := local.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}
	wg.Wait()
}
