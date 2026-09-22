package client_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wargasipil/san_tunnels/internal/client"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func writeConfig(t *testing.T, cfg string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// A configured port must survive into the resolved target, because that is
// what `connect` binds and what ssh then records in known_hosts.
func TestConfiguredPortResolves(t *testing.T) {
	path := writeConfig(t, `{"agents":{"box-01":{"url":"https://example:8443","port":2222}}}`)

	cfg, err := client.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	target, err := cfg.Resolve("box-01")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.Port != 2222 {
		t.Fatalf("port %d, want 2222", target.Port)
	}
}

// An unset port is 0, which means "any free one" rather than port zero.
func TestPortDefaultsToZero(t *testing.T) {
	path := writeConfig(t, `{"agents":{"box-01":{"url":"https://example:8443"}}}`)

	cfg, _ := client.LoadConfig(path)
	target, err := cfg.Resolve("box-01")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.Port != 0 {
		t.Fatalf("port %d, want 0", target.Port)
	}
}

func TestBadPortRejected(t *testing.T) {
	path := writeConfig(t, `{"agents":{"box-01":{"url":"https://example:8443","port":70000}}}`)

	cfg, _ := client.LoadConfig(path)
	_, err := cfg.Resolve("box-01")
	if err == nil {
		t.Fatal("accepted a port outside the valid range")
	}
	if !strings.Contains(err.Error(), "not a port number") {
		t.Fatalf("got %v, want the error to name the problem", err)
	}
}

// The port is written back out as configured, so round-tripping a config does
// not quietly drop it.
func TestPortRoundTrips(t *testing.T) {
	a := client.Agent{URL: "https://example:8443", Port: 2222}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"port":2222`) {
		t.Fatalf("marshalled as %s, want a port field", b)
	}

	var zero client.Agent
	zb, _ := json.Marshal(zero)
	if strings.Contains(string(zb), "port") {
		t.Fatalf("an unset port should be omitted, got %s", zb)
	}
}

// The alias is what ends up in known_hosts and, for anyone who adds the hosts
// lines, in DNS -- so it has to be a legal label whatever the agent is called.
func TestHostAlias(t *testing.T) {
	cases := map[string]string{
		"box-01":     "box-01.tunnels.internal",
		"BOX-01":     "box-01.tunnels.internal", // DNS is case-insensitive; be consistent
		"prod_db":    "prod-db.tunnels.internal",
		"a.b.c":      "a-b-c.tunnels.internal", // extra labels would change the zone
		"":           "agent.tunnels.internal",
		"!!!":        "---.tunnels.internal",
		"kadal jaya": "kadal-jaya.tunnels.internal",
		// Already suffixed: do not stack a second copy on.
		"box-01.tunnels.internal": "box-01.tunnels.internal",
	}
	for in, want := range cases {
		if got := client.HostAlias(in); got != want {
			t.Errorf("HostAlias(%q) = %q, want %q", in, got, want)
		}
	}
}

// Listen must bind the address it is given and report it, since the printed
// instructions and every saved GUI profile depend on that number.
func TestListenBindsRequestedPort(t *testing.T) {
	// Take a port, release it, then ask Listen for it: a free fixed port.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- client.Listen(ctx, client.Target{Name: "t", URL: "https://127.0.0.1:1"},
			"shell", addr, func(a net.Addr) { got <- a.String() }, quiet())
	}()

	select {
	case bound := <-got:
		if bound != addr {
			t.Fatalf("bound %s, want %s", bound, addr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Listen never reported a bound address")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Listen returned %v, want nil on cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Listen did not return after cancellation")
	}
}

// A taken port must fail rather than silently moving: ssh records the port,
// so drifting looks like the host key changed.
func TestListenFailsOnTakenPort(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold listen: %v", err)
	}
	defer held.Close()

	err = client.Listen(context.Background(), client.Target{Name: "t", URL: "https://127.0.0.1:1"},
		"shell", held.Addr().String(), nil, quiet())
	if err == nil {
		t.Fatal("Listen succeeded on a port already in use")
	}
	if !strings.Contains(err.Error(), held.Addr().String()) {
		t.Fatalf("got %v, want the error to name the address", err)
	}
}
