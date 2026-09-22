package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey returns the agent's persistent ed25519 host key,
// generating it on first run.
//
// It must persist: clients pin this key in known_hosts, and that pinning is
// what stops an intermediary substituting its own and reading the session.
func LoadOrCreateHostKey(path string) (gossh.Signer, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		signer, err := gossh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, err)
		}
		return signer, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read host key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "san_tunnels")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create key dir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("write host key %s: %w", path, err)
	}

	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("build signer: %w", err)
	}
	return signer, nil
}

// AuthorizedKeys is the agent's own key list, deliberately separate from the
// system's ~/.ssh/authorized_keys so the agent does not inherit whatever else
// grants access to the host.
type AuthorizedKeys struct {
	mu   sync.RWMutex
	path string
	keys []gossh.PublicKey
}

// LoadAuthorizedKeys reads path. A missing file is not an error: it means no
// key is trusted yet, and every authentication attempt will be refused.
func LoadAuthorizedKeys(path string) (*AuthorizedKeys, error) {
	a := &AuthorizedKeys{path: path}
	if err := a.Reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// Reload re-reads the file, so authorizing a key does not need a restart.
func (a *AuthorizedKeys) Reload() error {
	b, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		a.mu.Lock()
		a.keys = nil
		a.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("read authorized keys %s: %w", a.path, err)
	}

	var keys []gossh.PublicKey
	rest := b
	for len(rest) > 0 {
		key, _, _, remaining, err := gossh.ParseAuthorizedKey(rest)
		if err != nil {
			// Skip the offending line rather than refusing every key because
			// one entry is malformed.
			if i := indexNewline(rest); i >= 0 {
				rest = rest[i+1:]
				continue
			}
			break
		}
		keys = append(keys, key)
		rest = remaining
	}

	a.mu.Lock()
	a.keys = keys
	a.mu.Unlock()
	return nil
}

// Has reports whether key is trusted.
func (a *AuthorizedKeys) Has(key gossh.PublicKey) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	want := key.Marshal()
	for _, k := range a.keys {
		// Constant time, so a trusted key cannot be discovered by timing the
		// comparison against candidates.
		if subtle.ConstantTimeCompare(k.Marshal(), want) == 1 {
			return true
		}
	}
	return false
}

// Len reports how many keys are trusted.
func (a *AuthorizedKeys) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.keys)
}

// Append adds an authorized_keys line, rejecting anything that does not parse
// so a typo cannot quietly grant nothing while looking like it worked.
func (a *AuthorizedKeys) Append(line string) error {
	line = strings.TrimSpace(line)
	if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line)); err != nil {
		return fmt.Errorf("not a valid authorized_keys line: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if dir := filepath.Dir(a.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create key dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open authorized keys %s: %w", a.path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("write authorized keys: %w", err)
	}

	key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err == nil {
		a.keys = append(a.keys, key)
	}
	return nil
}

func indexNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}
