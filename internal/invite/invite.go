// Package invite carries everything an entry host needs to reach an agent, in
// one pasteable string.
//
// Registering a client by hand means copying a URL, a token and a certificate
// fingerprint without mistyping any of them, and the fingerprint is the one
// people skip -- which is exactly the one that closes the trust-on-first-use
// window. Moving all three together makes the safe path the easy one.
package invite

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Prefix marks the string as ours.
//
// It is deliberately shaped like GitHub's ghp_ tokens: a fixed, searchable
// prefix is what lets secret scanners and pre-commit hooks recognise one of
// these on sight. An invite carries a bearer token, so it wants to be as
// greppable as any other credential.
const Prefix = "san1_"

// Invite is the payload. Everything but the URL is optional, so an agent with
// no token or running cleartext can still be registered.
type Invite struct {
	URL string `json:"url"`
	// Token authenticates to the agent's transport. Its presence is what
	// makes an invite a secret.
	Token string `json:"token,omitempty"`
	// TLSFingerprint pins the agent's certificate. Carried out of band like
	// this, it removes the first-use window rather than papering over it.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	// HostKey is the SSH host key fingerprint, for a human to compare against
	// what ssh shows on first connect. Nothing verifies it automatically:
	// known_hosts is ssh's to own, not ours.
	HostKey string `json:"host_key,omitempty"`
	// User is the suggested SSH login, for the generated ssh config block.
	User string `json:"user,omitempty"`
}

// Encode renders an invite as one pasteable token.
func Encode(i Invite) (string, error) {
	if i.URL == "" {
		return "", errors.New("an invite needs a url")
	}
	b, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("encode invite: %w", err)
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Decode parses one, tolerating the whitespace a copy-paste picks up.
func Decode(s string) (Invite, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Prefix) {
		return Invite{}, fmt.Errorf("not an invite: expected it to start with %q", Prefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
	if err != nil {
		return Invite{}, fmt.Errorf("decode invite: %w", err)
	}

	var i Invite
	if err := json.Unmarshal(b, &i); err != nil {
		return Invite{}, fmt.Errorf("parse invite: %w", err)
	}
	if i.URL == "" {
		return Invite{}, errors.New("invite carries no url")
	}
	return i, nil
}

// Redact returns the invite with its token replaced, for logging.
func Redact(i Invite) Invite {
	if i.Token != "" {
		i.Token = "(redacted)"
	}
	return i
}
