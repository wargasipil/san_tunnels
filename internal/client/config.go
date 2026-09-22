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
	return Target{
		Name:      name,
		URL:       a.URL,
		Token:     a.Token,
		User:      a.User,
		Insecure:  a.Insecure,
		Transport: transport,
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
