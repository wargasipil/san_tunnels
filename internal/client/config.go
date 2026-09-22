package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Config maps agent names to where they live.
//
// The name is the unit the user deals with: `ssh box-01` resolves through this
// file, which is also why moving to a hub is a config change rather than a code
// change -- the same name simply points at the hub instead of the host.
type Config struct {
	Agents map[string]Agent `json:"agents"`
}

// Agent is one entry in the client config.
type Agent struct {
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
	// User is the SSH user to put in the generated ssh config block.
	User string `json:"user,omitempty"`
	// Insecure skips TLS verification. Development only.
	Insecure bool `json:"insecure,omitempty"`
	// TLSFingerprint pins the agent's certificate, as printed by
	// `san_tunnels server fingerprint`. Set, nothing else is accepted, and it
	// overrides whatever trust on first use recorded.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	// Port is the local port `client connect` binds for this agent. Unset, it
	// takes a free one.
	//
	// Worth setting for anything you connect to repeatedly: ssh records the
	// port in known_hosts, and GUI clients that cannot set HostKeyAlias have
	// nothing but the port to tell one agent from another.
	Port int `json:"port,omitempty"`
	// Transport is "connect" (the default) or "ws". Set it to "ws" only when
	// something in the path cannot carry a full-duplex HTTP/2 stream; the
	// agent's own error message says so when that is the case.
	Transport string `json:"transport,omitempty"`
}

// DefaultConfigPath is ~/.config/san_tunnels/config.json.
func DefaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(dir, "san_tunnels", "config.json"), nil
}

// LoadConfig reads path. A missing file yields an empty config, so `client`
// commands can still report a useful error naming the agent that is unknown.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{Agents: map[string]Agent{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.Agents == nil {
		c.Agents = map[string]Agent{}
	}
	return &c, nil
}

// Save writes the config back, creating its directory if needed.
//
// 0600, because this file holds bearer tokens. The write goes to a temporary
// file first and is then renamed over the original, so an interrupted save
// cannot leave a half-written config where a working one used to be.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	b = append(b, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace config %s: %w", path, err)
	}
	return nil
}

// Set adds or replaces one agent.
func (c *Config) Set(name string, a Agent) {
	if c.Agents == nil {
		c.Agents = map[string]Agent{}
	}
	c.Agents[name] = a
}

// Resolve turns an agent name into a Target.
func (c *Config) Resolve(name string) (Target, error) {
	a, ok := c.Agents[name]
	if !ok {
		known := c.Names()
		if len(known) == 0 {
			return Target{}, fmt.Errorf("no agent named %q, and no agents are configured yet", name)
		}
		return Target{}, fmt.Errorf("no agent named %q; configured agents: %s", name, strings.Join(known, ", "))
	}
	if a.URL == "" {
		return Target{}, fmt.Errorf("agent %q has no url", name)
	}
	transport, err := ParseTransport(a.Transport)
	if err != nil {
		return Target{}, fmt.Errorf("agent %q: %w", name, err)
	}
	if a.Port < 0 || a.Port > 65535 {
		return Target{}, fmt.Errorf("agent %q has port %d, which is not a port number", name, a.Port)
	}
	return Target{
		Name:           name,
		URL:            a.URL,
		Token:          a.Token,
		User:           a.User,
		Insecure:       a.Insecure,
		Transport:      transport,
		TLSFingerprint: a.TLSFingerprint,
		Port:           a.Port,
	}, nil
}

// Names lists configured agents, sorted.
func (c *Config) Names() []string {
	out := make([]string, 0, len(c.Agents))
	for k := range c.Agents {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SSHConfigBlock renders the ~/.ssh/config entry for a target.
//
// This prints rather than edits. ~/.ssh/config belongs to the user, and
// OpenSSH resolves each keyword first-match-wins, so a `Host *` block above
// ours would silently shadow our User or IdentityFile. Appending is not
// reliably correct, prepending fights whatever else is in the file, and doing
// it properly means parsing and rewriting someone else's config.
func SSHConfigBlock(t Target, exe string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host %s\n", t.Name)
	fmt.Fprintf(&b, "  ProxyCommand %s client proxy %%h\n", exe)
	if t.User != "" {
		fmt.Fprintf(&b, "  User %s\n", t.User)
	}
	return b.String()
}
