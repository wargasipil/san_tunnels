// Command san_tunnels is both halves of the tunnel: `server` runs the agent on
// a target host, `client` runs on the entry host.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/wargasipil/san_tunnels/internal/agent"
	"github.com/wargasipil/san_tunnels/internal/client"
	"github.com/wargasipil/san_tunnels/internal/invite"
)

// version is stamped at build time.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := root().Run(ctx, os.Args); err != nil {
		// Always stderr: `client proxy` owns stdout for tunnel bytes.
		fmt.Fprintf(os.Stderr, "san_tunnels: %v\n", err)
		os.Exit(1)
	}
}

func root() *cli.Command {
	return &cli.Command{
		Name:    "san_tunnels",
		Usage:   "TCP tunnelling over Connect RPC, carrying SSH to hosts with no SSH daemon",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "debug, info, warn or error",
				Value:   "info",
				Sources: cli.EnvVars("SAN_TUNNELS_LOG_LEVEL"),
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			// All logging goes to stderr, everywhere, without exception.
			var level slog.Level
			if err := level.UnmarshalText([]byte(cmd.String("log-level"))); err != nil {
				return ctx, fmt.Errorf("bad --log-level %q", cmd.String("log-level"))
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
			return ctx, nil
		},
		Commands: []*cli.Command{serverCommand(), clientCommand()},
	}
}

// ---------------------------------------------------------------- server ---

func serverCommand() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Usage: "run the agent on a target host",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "listen", Value: ":8443", Usage: "address to listen on"},
			&cli.StringFlag{Name: "tls-cert", Usage: "TLS certificate file"},
			&cli.StringFlag{Name: "tls-key", Usage: "TLS key file"},
			&cli.BoolFlag{Name: "tls-auto", Usage: "generate and persist a self-signed certificate (the default when no other transport is given)"},
			&cli.StringSliceFlag{Name: "tls-host", Usage: "extra hostname or IP for the generated certificate (repeatable)"},
			&cli.BoolFlag{Name: "h2c", Usage: "serve cleartext HTTP/2 (only behind an L4 proxy)"},
			&cli.StringFlag{Name: "token", Sources: cli.EnvVars("SAN_TUNNELS_TOKEN"), Usage: "transport bearer token"},
			&cli.StringFlag{Name: "token-file", Usage: "file holding the transport bearer token"},
			&cli.StringFlag{Name: "host-key", Usage: "SSH host key path (generated on first run)"},
			&cli.StringFlag{Name: "authorized-keys", Usage: "our own authorized_keys path"},
			&cli.StringFlag{Name: "shell", Usage: "login shell to spawn (default: platform shell)"},
			&cli.StringSliceFlag{Name: "endpoint", Usage: "allowlisted TCP endpoint as name=host:port (repeatable)"},
			&cli.StringSliceFlag{Name: "ws-origin", Usage: "browser origin allowed to open a WebSocket tunnel (repeatable)"},
		},
		Action: runServer,
		Commands: []*cli.Command{
			{
				Name:      "authorize",
				Usage:     "add a public key to our authorized_keys",
				ArgsUsage: "<authorized_keys line, or - for stdin>",
				Flags:     []cli.Flag{&cli.StringFlag{Name: "authorized-keys"}},
				Action:    runAuthorize,
			},
			{
				Name:   "hostkey",
				Usage:  "print the host key fingerprint",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "host-key"}},
				Action: runHostKey,
			},
			{
				Name:  "fingerprint",
				Usage: "print the SSH host key and TLS certificate fingerprints",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "host-key"},
					&cli.StringFlag{Name: "tls-cert"},
					&cli.StringFlag{Name: "tls-key"},
					&cli.StringSliceFlag{Name: "tls-host"},
				},
				Action: runFingerprint,
			},
			{
				Name:  "init",
				Usage: "generate the agent's keys, certificate and token",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "host-key"},
					&cli.StringFlag{Name: "authorized-keys"},
					&cli.StringFlag{Name: "tls-cert"},
					&cli.StringFlag{Name: "tls-key"},
					&cli.BoolFlag{Name: "tls-auto"},
					&cli.StringSliceFlag{Name: "tls-host"},
					&cli.BoolFlag{Name: "h2c", Usage: "cleartext: generate no certificate"},
					&cli.StringFlag{Name: "token-file"},
					&cli.BoolFlag{Name: "force", Usage: "replace an existing token"},
				},
				Action: runInit,
			},
			{
				Name:  "invite",
				Usage: "print a pasteable registration token for an entry host",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "url", Usage: "the URL entry hosts reach this agent on (required)"},
					&cli.StringFlag{Name: "user", Usage: "suggested SSH login for the generated ssh config block"},
					&cli.StringFlag{Name: "host-key"},
					&cli.StringFlag{Name: "tls-cert"},
					&cli.StringFlag{Name: "tls-key"},
					&cli.BoolFlag{Name: "tls-auto"},
					&cli.StringSliceFlag{Name: "tls-host"},
					&cli.BoolFlag{Name: "h2c"},
					&cli.StringFlag{Name: "token", Sources: cli.EnvVars("SAN_TUNNELS_TOKEN")},
					&cli.StringFlag{Name: "token-file"},
				},
				Action: runInvite,
			},
			{
				Name:   "endpoints",
				Usage:  "list the endpoint allowlist",
				Flags:  []cli.Flag{&cli.StringSliceFlag{Name: "endpoint"}},
				Action: runEndpoints,
			},
		},
	}
}

func runServer(ctx context.Context, cmd *cli.Command) error {
	log := slog.Default()

	hostKeyPath, err := agentPath(cmd.String("host-key"), "host_key")
	if err != nil {
		return err
	}
	authPath, err := agentPath(cmd.String("authorized-keys"), "authorized_keys")
	if err != nil {
		return err
	}
	token, err := resolveToken(cmd.String("token"), cmd.String("token-file"))
	if err != nil {
		return err
	}
	endpoints, err := parseEndpoints(cmd.StringSlice("endpoint"))
	if err != nil {
		return err
	}
	tlsCert, tlsKey, tlsAuto, err := resolveTLS(cmd)
	if err != nil {
		return err
	}

	hostKey, err := agent.LoadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return err
	}
	authorized, err := agent.LoadAuthorizedKeys(authPath)
	if err != nil {
		return err
	}
	if authorized.Len() == 0 {
		log.Warn("no authorized keys: every session will be refused",
			"path", authPath,
			"hint", "san_tunnels server authorize \"$(cat ~/.ssh/id_ed25519.pub)\"")
	}

	sshServer, err := agent.NewSSHServer(agent.SSHOptions{
		HostKey:    hostKey,
		Authorized: authorized,
		Shell:      cmd.String("shell"),
		Log:        log,
	})
	if err != nil {
		return err
	}
	svc, err := agent.NewService(sshServer, endpoints, log)
	if err != nil {
		return err
	}

	log.Info("agent starting",
		"version", version,
		"host_key", hostKeyPath,
		"authorized_keys", authPath,
		"authorized_count", authorized.Len(),
		"endpoints", len(svc.Endpoints()))

	return agent.Serve(ctx, agent.ServeOptions{
		Listen:    cmd.String("listen"),
		Token:     token,
		TLSCert:   tlsCert,
		TLSKey:    tlsKey,
		TLSAuto:   tlsAuto,
		TLSHosts:  cmd.StringSlice("tls-host"),
		H2C:       cmd.Bool("h2c"),
		WSOrigins: cmd.StringSlice("ws-origin"),
		Service:   svc,
		Log:       log,
	})
}

func runAuthorize(ctx context.Context, cmd *cli.Command) error {
	arg := cmd.Args().First()
	if arg == "" {
		return errors.New("give an authorized_keys line, or - to read one from stdin")
	}

	line := arg
	if arg == "-" {
		b, err := readAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read key from stdin: %w", err)
		}
		line = strings.TrimSpace(b)
	}

	authPath, err := agentPath(cmd.String("authorized-keys"), "authorized_keys")
	if err != nil {
		return err
	}
	authorized, err := agent.LoadAuthorizedKeys(authPath)
	if err != nil {
		return err
	}
	if err := authorized.Append(line); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "authorized; %s now holds %d key(s)\n", authPath, authorized.Len())
	return nil
}

func runHostKey(ctx context.Context, cmd *cli.Command) error {
	path, err := agentPath(cmd.String("host-key"), "host_key")
	if err != nil {
		return err
	}
	signer, err := agent.LoadOrCreateHostKey(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "%s\n%s %s\n", path, signer.PublicKey().Type(), fingerprint(signer))
	return nil
}

// runInit brings an agent up to the point where it only needs an authorized
// key.
//
// The token is the reason this exists. The host key and certificate are
// already generated on first run, but the token has always had to be invented
// by hand -- so the overwhelmingly common setup is one with no token at all,
// which leaves every TCP endpoint reachable by anyone who can dial the port.
// Generating a good one by default inverts that: you now have to take the
// token away on purpose rather than never think of it.
func runInit(ctx context.Context, cmd *cli.Command) error {
	hostKeyPath, err := agentPath(cmd.String("host-key"), "host_key")
	if err != nil {
		return err
	}
	authPath, err := agentPath(cmd.String("authorized-keys"), "authorized_keys")
	if err != nil {
		return err
	}
	tokenPath := cmd.String("token-file")
	if tokenPath == "" {
		if tokenPath, err = agentPath("", "token"); err != nil {
			return err
		}
	}

	signer, err := agent.LoadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ssh host key    %s\n", fingerprint(signer))

	certPath, keyPath, _, err := resolveTLS(cmd)
	if err != nil {
		return err
	}
	if certPath != "" && keyPath != "" {
		cert, cerr := agent.LoadOrCreateTLSCert(certPath, keyPath, cmd.StringSlice("tls-host"))
		if cerr != nil {
			return cerr
		}
		fp, ferr := agent.LeafFingerprint(cert)
		if ferr != nil {
			return ferr
		}
		fmt.Fprintf(os.Stdout, "tls certificate %s\n", fp)
	} else {
		fmt.Fprintln(os.Stdout, "tls certificate (none: --h2c, cleartext behind an L4 proxy)")
	}

	created, err := ensureToken(tokenPath, cmd.Bool("force"))
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(os.Stdout, "token           written to %s\n", tokenPath)
	} else {
		fmt.Fprintf(os.Stdout, "token           kept, already at %s (--force to replace)\n", tokenPath)
	}

	authorized, err := agent.LoadAuthorizedKeys(authPath)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout)
	if authorized.Len() == 0 {
		fmt.Fprintf(os.Stdout, "No keys are authorized yet, so every session will be refused:\n"+
			"  san_tunnels server authorize \"$(cat ~/.ssh/id_ed25519.pub)\"\n\n")
	}
	fmt.Fprintf(os.Stdout, "Then run the agent, and hand an entry host its registration token:\n"+
		"  san_tunnels server --token-file %s\n"+
		"  san_tunnels server invite --url https://<this host>:8443\n", tokenPath)
	return nil
}

// ensureToken writes a fresh random token unless one is already there.
//
// Replacing a token that exists would lock out every client already holding
// it, so that needs saying out loud with --force.
func ensureToken(path string, force bool) (created bool, err error) {
	if !force {
		if _, statErr := os.Stat(path); statErr == nil {
			return false, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return false, fmt.Errorf("check token file %s: %w", path, statErr)
		}
	}

	// 32 bytes of CSPRNG output: far past guessing, and the comparison
	// against it is constant time on the agent side.
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return false, fmt.Errorf("generate token: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("create agent directory: %w", err)
	}
	if err = os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(buf)+"\n"), 0o600); err != nil {
		return false, fmt.Errorf("write token file %s: %w", path, err)
	}
	return true, nil
}

// runInvite prints everything an entry host needs, as one string.
func runInvite(ctx context.Context, cmd *cli.Command) error {
	rawURL := cmd.String("url")
	if rawURL == "" {
		// The agent cannot know the name it is reached by: it may be behind
		// NAT, a proxy, or several names at once.
		return errors.New("--url is required: the address entry hosts reach this agent on, e.g. https://box-01.example:8443")
	}

	hostKeyPath, err := agentPath(cmd.String("host-key"), "host_key")
	if err != nil {
		return err
	}
	signer, err := agent.LoadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return err
	}

	tokenPath := cmd.String("token-file")
	if tokenPath == "" {
		if p, perr := agentPath("", "token"); perr == nil {
			if _, statErr := os.Stat(p); statErr == nil {
				tokenPath = p
			}
		}
	}
	token, err := resolveToken(cmd.String("token"), tokenPath)
	if err != nil {
		return err
	}

	inv := invite.Invite{
		URL:     rawURL,
		Token:   token,
		HostKey: fingerprint(signer),
		User:    cmd.String("user"),
	}

	certPath, keyPath, _, err := resolveTLS(cmd)
	if err != nil {
		return err
	}
	if certPath != "" && keyPath != "" {
		cert, cerr := agent.LoadOrCreateTLSCert(certPath, keyPath, cmd.StringSlice("tls-host"))
		if cerr != nil {
			return cerr
		}
		if inv.TLSFingerprint, err = agent.LeafFingerprint(cert); err != nil {
			return err
		}
	}

	blob, err := invite.Encode(inv)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, blob)

	// To stderr, so piping the blob somewhere still yields just the blob.
	fmt.Fprintf(os.Stderr, "\nRegister it on the entry host:\n"+
		"  san_tunnels client add <name> --from <the string above>\n")
	if token != "" {
		fmt.Fprintf(os.Stderr, "\nThis carries the agent's token: treat it as a password. It grants a\n"+
			"tunnel to anyone who holds it -- an SSH key is still needed for a shell,\n"+
			"but any allowlisted TCP endpoint is not behind one.\n")
	}
	return nil
}

// runFingerprint prints both identities an operator may need to pin. They are
// printed together because they answer the same question -- "is this really my
// agent?" -- at two different layers.
func runFingerprint(ctx context.Context, cmd *cli.Command) error {
	hostKeyPath, err := agentPath(cmd.String("host-key"), "host_key")
	if err != nil {
		return err
	}
	signer, err := agent.LoadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return err
	}

	certPath, keyPath, _, err := resolveTLS(cmd)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ssh host key   %s %s\n", signer.PublicKey().Type(), fingerprint(signer))

	if certPath == "" || keyPath == "" {
		fmt.Fprintln(os.Stdout, "tls certificate  (none: agent is configured for cleartext h2c)")
		return nil
	}
	cert, err := agent.LoadOrCreateTLSCert(certPath, keyPath, cmd.StringSlice("tls-host"))
	if err != nil {
		return err
	}
	fp, err := agent.LeafFingerprint(cert)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "tls certificate %s\n", fp)
	fmt.Fprintf(os.Stdout, "\nPin it in the client config:\n  \"tls_fingerprint\": %q\n", fp)
	return nil
}

func runEndpoints(ctx context.Context, cmd *cli.Command) error {
	endpoints, err := parseEndpoints(cmd.StringSlice("endpoint"))
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "%-16s %s\n", agent.ShellEndpoint, "embedded ssh server (in-process, no socket)")
	for name, addr := range endpoints {
		fmt.Fprintf(os.Stdout, "%-16s %s\n", name, addr)
	}
	return nil
}

// ---------------------------------------------------------------- client ---

// transportFlag overrides the transport configured for an agent.
//
// It is a per-invocation override, not a preference: the durable choice
// belongs in the config file next to the URL it applies to.
func transportFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    "transport",
		Usage:   "`connect` (HTTP/2, default) or ws (WebSocket over HTTP/1.1)",
		Sources: cli.EnvVars("SAN_TUNNELS_TRANSPORT"),
	}
}

func clientCommand() *cli.Command {
	configFlag := &cli.StringFlag{
		Name:    "config",
		Usage:   "client config file (default: <user config dir>/san_tunnels/config.json)",
		Sources: cli.EnvVars("SAN_TUNNELS_CONFIG"),
	}

	return &cli.Command{
		Name:  "client",
		Usage: "connect to an agent from the entry host",
		Flags: []cli.Flag{configFlag},
		Commands: []*cli.Command{
			{
				Name:      "proxy",
				Usage:     "ssh ProxyCommand: bridge stdio to a tunnel stream",
				ArgsUsage: "<agent name>",
				// Nothing but tunnel bytes may reach stdout, so urfave itself
				// is pointed at stderr for this command.
				Writer:    os.Stderr,
				ErrWriter: os.Stderr,
				Flags: []cli.Flag{
					configFlag,
					&cli.StringFlag{Name: "endpoint", Value: agent.ShellEndpoint, Usage: "endpoint to open"},
					&cli.StringFlag{Name: "token", Sources: cli.EnvVars("SAN_TUNNELS_TOKEN")},
					&cli.BoolFlag{Name: "insecure", Usage: "skip TLS verification (development only)"},
					&cli.StringFlag{Name: "tls-fingerprint", Usage: "pin the agent certificate, as printed by 'server fingerprint'"},
					transportFlag(),
				},
				Action: runProxy,
			},
			{
				Name:      "config",
				Usage:     "print the ~/.ssh/config block for an agent",
				ArgsUsage: "<agent name>",
				Flags:     []cli.Flag{configFlag},
				Action:    runSSHConfig,
			},
			{
				Name:      "connect",
				Usage:     "open a local port that forwards to an agent endpoint",
				ArgsUsage: "<agent name>",
				Flags: []cli.Flag{
					configFlag,
					&cli.StringFlag{Name: "endpoint", Value: agent.ShellEndpoint, Usage: "endpoint to open"},
					&cli.StringFlag{
						Name:  "listen",
						Usage: "local address to bind (default: the agent's configured port, else a free loopback port)",
					},
					&cli.StringFlag{Name: "token", Sources: cli.EnvVars("SAN_TUNNELS_TOKEN")},
					&cli.BoolFlag{Name: "insecure", Usage: "skip TLS verification (development only)"},
					&cli.StringFlag{Name: "tls-fingerprint", Usage: "pin the agent certificate, as printed by 'server fingerprint'"},
					transportFlag(),
				},
				Action: runConnect,
			},
			{
				Name:      "check",
				Usage:     "prove the path to an agent is full-duplex",
				ArgsUsage: "<agent name>",
				Flags: []cli.Flag{
					configFlag,
					&cli.StringFlag{Name: "token", Sources: cli.EnvVars("SAN_TUNNELS_TOKEN")},
					&cli.BoolFlag{Name: "insecure"},
					&cli.StringFlag{Name: "tls-fingerprint"},
					&cli.DurationFlag{Name: "timeout", Value: 10 * time.Second},
					transportFlag(),
				},
				Action: runCheck,
			},
			{
				Name:   "list",
				Usage:  "list configured agents",
				Flags:  []cli.Flag{configFlag},
				Action: runList,
			},
			{
				Name:      "add",
				Usage:     "register an agent in the client config",
				ArgsUsage: "<name> [url]",
				Flags: []cli.Flag{
					configFlag,
					&cli.StringFlag{Name: "from", Usage: "registration token from `server invite`"},
					&cli.StringFlag{Name: "token", Sources: cli.EnvVars("SAN_TUNNELS_TOKEN")},
					&cli.StringFlag{Name: "user", Usage: "SSH login for the generated ssh config block"},
					&cli.IntFlag{Name: "port", Usage: "local port for `client connect` (0 for any free one)"},
					&cli.StringFlag{Name: "tls-fingerprint", Usage: "pin the agent certificate"},
					&cli.BoolFlag{Name: "insecure", Usage: "skip TLS verification (development only)"},
					&cli.BoolFlag{Name: "force", Usage: "replace an agent of the same name"},
					transportFlag(),
				},
				Action: runAdd,
			},
			{
				Name:   "hosts",
				Usage:  "print hosts-file lines giving each agent a local name",
				Flags:  []cli.Flag{configFlag},
				Action: runHosts,
			},
		},
	}
}

func runProxy(ctx context.Context, cmd *cli.Command) error {
	target, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	// Everything above this line must fail before a single byte reaches
	// stdout, or it lands mid-handshake and ssh reports nonsense.
	return client.Proxy(ctx, target, cmd.String("endpoint"), os.Stdin, os.Stdout)
}

// runConnect binds a local port and forwards it to an agent endpoint.
//
// The counterpart to `proxy`, for clients that cannot run an ssh
// ProxyCommand: GUI SSH clients, and every database or TCP tool that only
// knows how to reach a host and a port.
func runConnect(ctx context.Context, cmd *cli.Command) error {
	target, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	endpoint := cmd.String("endpoint")

	ready := func(addr net.Addr) {
		fmt.Fprintf(os.Stdout, "listening on %s -> %s (%s)\n\n", addr, target.Name, endpoint)

		_, port, splitErr := net.SplitHostPort(addr.String())
		switch {
		case splitErr != nil:
			// Nothing useful to suggest; the address line above still stands.
		case endpoint == agent.ShellEndpoint:
			user := target.User
			if user == "" {
				user = "<user>"
			}
			alias := client.HostAlias(target.Name)
			fmt.Fprintf(os.Stdout, "  ssh -p %s -o HostKeyAlias=%s %s@localhost\n\n", port, alias, user)
			// Without HostKeyAlias every agent reached this way looks like
			// localhost to ssh, so they would all share one known_hosts entry
			// keyed on the port -- and the port moving would then read as the
			// host key having changed.
			fmt.Fprintf(os.Stdout, "HostKeyAlias keeps known_hosts keyed on %s rather than on the port,\n"+
				"so the host key stays pinned to this agent even if the port moves.\n"+
				"For a client that cannot set it, run `san_tunnels client hosts`.\n", alias)
		default:
			fmt.Fprintf(os.Stdout, "  point any client at localhost:%s\n\n", port)
			fmt.Fprintf(os.Stdout, "Anyone on this machine can use this port while it is open: a TCP\n"+
				"endpoint has no SSH layer behind it, only the token you already hold.\n")
		}
		fmt.Fprint(os.Stdout, "\nCtrl-C to close.\n")
	}

	addr := listenAddr(cmd.String("listen"), target)
	err = client.Listen(ctx, target, endpoint, addr, ready, slog.Default())
	if err != nil && target.Port != 0 && !cmd.IsSet("listen") {
		// Do not quietly fall back to a free port. ssh records the port in
		// known_hosts, so an agent that moves looks exactly like a host whose
		// key changed -- and a warning you learn to wave through is worse
		// than the collision.
		return fmt.Errorf("%w\n\n"+
			"Agent %q is pinned to port %d in the client config, and is not moved to a\n"+
			"free port on purpose: ssh records the port in known_hosts, so drifting would\n"+
			"look like the host key changed. Free that port, or change \"port\" for %q.",
			err, target.Name, target.Port, target.Name)
	}
	return err
}

// runAdd registers an agent, from an invite or from flags and prompts.
func runAdd(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" {
		var err error
		if name, err = prompt("agent name"); err != nil {
			return err
		}
	}
	if name == "" {
		return errors.New("give an agent name")
	}

	cfg, path, err := loadClientConfig(cmd)
	if err != nil {
		return err
	}
	if _, exists := cfg.Agents[name]; exists && !cmd.Bool("force") {
		return fmt.Errorf("agent %q is already in %s; pass --force to replace it", name, path)
	}

	entry := client.Agent{
		Token:          cmd.String("token"),
		User:           cmd.String("user"),
		Port:           int(cmd.Int("port")),
		TLSFingerprint: cmd.String("tls-fingerprint"),
		Insecure:       cmd.Bool("insecure"),
		Transport:      cmd.String("transport"),
	}
	entry.URL = cmd.Args().Get(1)

	// An invite fills everything in at once, and brings the certificate
	// fingerprint out of band, which is the whole reason to prefer it.
	var fromInvite bool
	if blob := cmd.String("from"); blob != "" {
		inv, derr := invite.Decode(blob)
		if derr != nil {
			return derr
		}
		fromInvite = true
		entry.URL = inv.URL
		if entry.Token == "" {
			entry.Token = inv.Token
		}
		if entry.User == "" {
			entry.User = inv.User
		}
		if entry.TLSFingerprint == "" {
			entry.TLSFingerprint = inv.TLSFingerprint
		}
		if inv.HostKey != "" {
			fmt.Fprintf(os.Stderr, "ssh host key in the invite: %s\n"+
				"  compare it with what ssh shows on first connect.\n", inv.HostKey)
		}
	}

	if entry.URL == "" {
		if entry.URL, err = prompt("agent url (e.g. https://box-01.example:8443)"); err != nil {
			return err
		}
	}
	if entry.URL == "" {
		return errors.New("give the agent's url")
	}

	// Without an invite there is no out-of-band fingerprint, so offer the
	// weaker thing: read the certificate and show it, for the operator to
	// compare against `server fingerprint` on the agent.
	if !fromInvite && entry.TLSFingerprint == "" && !entry.Insecure {
		fp, perr := client.ProbeFingerprint(ctx, entry.URL)
		switch {
		case perr != nil:
			fmt.Fprintf(os.Stderr, "could not read the agent's certificate (%v);\n"+
				"  adding it unpinned -- the first connection will record whatever it sees.\n", perr)
		case fp != "":
			entry.TLSFingerprint = fp
			fmt.Fprintf(os.Stderr, "certificate pinned %s\n"+
				"  this came from the connection it authenticates, so verify it against\n"+
				"  `san_tunnels server fingerprint` on the agent.\n", fp)
		}
	}

	cfg.Set(name, entry)
	if err := cfg.Save(path); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "added %s -> %s (%s)\n", name, entry.URL, path)
	target, err := cfg.Resolve(name)
	if err != nil {
		return err
	}
	exe, exeErr := os.Executable()
	if exeErr != nil || exe == "" {
		exe = "san_tunnels"
	}
	fmt.Fprintf(os.Stdout, "\n%s", client.SSHConfigBlock(target, exe))
	fmt.Fprintf(os.Stdout, "\nCheck it with: san_tunnels client check %s\n", name)
	return nil
}

// prompt asks for one value on stderr.
//
// stderr because stdout carries output a caller may be piping, and the same
// rule holds everywhere in this tool. A missing value is an error rather than
// a prompt when stdin is not a terminal: a script that hangs waiting for
// input nobody is there to give is worse than one that fails.
func prompt(label string) (string, error) {
	// term.IsTerminal rather than a ModeCharDevice check on Stat: on Windows
	// NUL is itself a character device, so redirecting from /dev/null looks
	// like a terminal to that test and we would print a prompt nobody can
	// answer, then fail with the wrong reason.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("%s is required (stdin is not a terminal, so there is nobody to ask)", label)
	}

	fmt.Fprintf(os.Stderr, "%s: ", label)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		if serr := sc.Err(); serr != nil {
			return "", fmt.Errorf("read %s: %w", label, serr)
		}
		return "", fmt.Errorf("no %s given", label)
	}
	return strings.TrimSpace(sc.Text()), nil
}

// runHosts prints the hosts-file lines that make agent names resolve.
//
// It prints rather than edits, for the reason `client config` does: the hosts
// file is not ours. It is worse than ~/.ssh/config on both counts -- it needs
// administrator rights, and it is shared with every user and process on the
// machine -- so quietly rewriting it would be the wrong kind of convenient.
func runHosts(ctx context.Context, cmd *cli.Command) error {
	cfg, path, err := loadClientConfig(cmd)
	if err != nil {
		return err
	}
	names := cfg.Names()
	if len(names) == 0 {
		fmt.Fprintf(os.Stdout, "no agents configured in %s\n", path)
		return nil
	}

	fmt.Fprintf(os.Stdout, "# add to %s%s\n", hostsFilePath(), hostsFileNote())
	for _, n := range names {
		fmt.Fprintf(os.Stdout, "127.0.0.1  %s\n", client.HostAlias(n))
	}
	fmt.Fprint(os.Stdout, "\n"+
		"Only needed for clients that cannot set HostKeyAlias -- PuTTY, WinSCP and\n"+
		"most GUI tools -- which otherwise file every agent's host key under\n"+
		"localhost and cannot tell them apart. With these lines they reach an agent\n"+
		"by name, and store its key under that name.\n\n"+
		"`ssh` itself needs none of this: `client connect` prints a HostKeyAlias.\n")
	return nil
}

func hostsFilePath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

func hostsFileNote() string {
	if runtime.GOOS == "windows" {
		return " (needs Administrator)"
	}
	return " (needs root)"
}

// listenAddr decides where connect binds.
//
// Precedence: an explicit --listen, then the agent's configured port, then a
// free loopback port.
func listenAddr(flag string, t client.Target) string {
	if flag != "" {
		return flag
	}
	if t.Port != 0 {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(t.Port))
	}
	return client.DefaultListen
}

func runSSHConfig(ctx context.Context, cmd *cli.Command) error {
	target, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "san_tunnels"
	}
	fmt.Fprint(os.Stdout, client.SSHConfigBlock(target, exe))
	return nil
}

func runCheck(ctx context.Context, cmd *cli.Command) error {
	target, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	if err := client.Check(ctx, target, cmd.Duration("timeout")); err != nil {
		return err
	}
	// Do not claim the WebSocket probe proved duplex. It cannot fail that
	// way -- a WebSocket is full-duplex by construction -- and saying
	// otherwise would make a passing check mean more than it does.
	if target.Transport == client.TransportWS {
		fmt.Fprintf(os.Stdout, "ok: %s is reachable over websocket and accepted the token\n", target.Name)
		return nil
	}
	fmt.Fprintf(os.Stdout, "ok: %s is reachable and the path is full-duplex\n", target.Name)
	return nil
}

func runList(ctx context.Context, cmd *cli.Command) error {
	cfg, path, err := loadClientConfig(cmd)
	if err != nil {
		return err
	}
	names := cfg.Names()
	if len(names) == 0 {
		fmt.Fprintf(os.Stdout, "no agents configured in %s\n", path)
		return nil
	}
	for _, n := range names {
		a := cfg.Agents[n]
		transport, err := client.ParseTransport(a.Transport)
		if err != nil {
			return fmt.Errorf("agent %q: %w", n, err)
		}
		port := "-"
		if a.Port != 0 {
			port = strconv.Itoa(a.Port)
		}
		fmt.Fprintf(os.Stdout, "%-20s %-40s %-8s port %s\n", n, a.URL, transport, port)
	}
	return nil
}

// ----------------------------------------------------------------- utils ---

func loadClientConfig(cmd *cli.Command) (*client.Config, string, error) {
	path := cmd.String("config")
	if path == "" {
		p, err := client.DefaultConfigPath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	cfg, err := client.LoadConfig(path)
	if err != nil {
		return nil, "", err
	}
	return cfg, path, nil
}

func resolveTarget(cmd *cli.Command) (client.Target, error) {
	name := cmd.Args().First()
	if name == "" {
		return client.Target{}, errors.New("give an agent name")
	}
	cfg, _, err := loadClientConfig(cmd)
	if err != nil {
		return client.Target{}, err
	}
	target, err := cfg.Resolve(name)
	if err != nil {
		return client.Target{}, err
	}
	if t := cmd.String("token"); t != "" {
		target.Token = t
	}
	if cmd.Bool("insecure") {
		target.Insecure = true
	}
	if fp := cmd.String("tls-fingerprint"); fp != "" {
		target.TLSFingerprint = fp
	}

	// Trust on first use, so a self-signed agent needs no fingerprint copied
	// by hand. The notice goes to stderr because `client proxy` owns stdout.
	knownPath, err := client.DefaultKnownAgentsPath()
	if err == nil {
		if known, err := client.LoadKnownAgents(knownPath); err == nil {
			target.Known = known
			target.OnTrust = func(name, fingerprint string) {
				fmt.Fprintf(os.Stderr,
					"san_tunnels: trusting agent %q on first use: %s\n"+
						"  recorded in %s; a different certificate will be refused from now on\n",
					name, fingerprint, knownPath)
			}
		}
	}

	if v := cmd.String("transport"); v != "" {
		transport, err := client.ParseTransport(v)
		if err != nil {
			return client.Target{}, err
		}
		target.Transport = transport
	}
	return target, nil
}

// agentPath resolves a flag value, falling back to the user config dir.
func agentPath(flag, name string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(dir, "san_tunnels", name), nil
}

func resolveToken(token, file string) (string, error) {
	if token != "" && file != "" {
		return "", errors.New("--token and --token-file are mutually exclusive")
	}
	if file == "" {
		return token, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read token file %s: %w", file, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// resolveTLS decides how the agent serves.
//
// The default is a self-signed certificate rather than cleartext, so that
// `san_tunnels server` alone is both runnable and encrypted. Cleartext stays
// available, but only by asking for it: h2c leaks the bearer token and every
// non-shell endpoint in plaintext, which is not something to fall into by
// forgetting a flag.
func resolveTLS(cmd *cli.Command) (certPath, keyPath string, auto bool, err error) {
	certPath = cmd.String("tls-cert")
	keyPath = cmd.String("tls-key")
	auto = cmd.Bool("tls-auto")

	explicit := certPath != "" && keyPath != ""
	if (certPath == "") != (keyPath == "") {
		return "", "", false, errors.New("--tls-cert and --tls-key must be given together")
	}
	if !explicit && !cmd.Bool("h2c") {
		auto = true
	}
	if auto && !explicit {
		if certPath, err = agentPath("", "tls_cert.pem"); err != nil {
			return "", "", false, err
		}
		if keyPath, err = agentPath("", "tls_key.pem"); err != nil {
			return "", "", false, err
		}
	}
	return certPath, keyPath, auto, nil
}

func readAll(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func fingerprint(s gossh.Signer) string {
	return gossh.FingerprintSHA256(s.PublicKey())
}

// parseEndpoints turns name=host:port pairs into the allowlist.
func parseEndpoints(vals []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range vals {
		name, addr, ok := strings.Cut(v, "=")
		if !ok || name == "" || addr == "" {
			return nil, fmt.Errorf("bad --endpoint %q: want name=host:port", v)
		}
		if name == agent.ShellEndpoint {
			return nil, fmt.Errorf("endpoint %q is reserved for the embedded ssh server", name)
		}
		out[name] = addr
	}
	return out, nil
}
