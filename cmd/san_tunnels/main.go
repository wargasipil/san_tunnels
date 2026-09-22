// Command san_tunnels is both halves of the tunnel: `server` runs the agent on
// a target host, `client` runs on the entry host.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"
	gossh "golang.org/x/crypto/ssh"

	"github.com/wargasipil/san_tunnels/internal/agent"
	"github.com/wargasipil/san_tunnels/internal/client"
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
		TLSCert:   cmd.String("tls-cert"),
		TLSKey:    cmd.String("tls-key"),
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
				Name:      "check",
				Usage:     "prove the path to an agent is full-duplex",
				ArgsUsage: "<agent name>",
				Flags: []cli.Flag{
					configFlag,
					&cli.StringFlag{Name: "token", Sources: cli.EnvVars("SAN_TUNNELS_TOKEN")},
					&cli.BoolFlag{Name: "insecure"},
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
		fmt.Fprintf(os.Stdout, "%-20s %-40s %s\n", n, a.URL, transport)
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
