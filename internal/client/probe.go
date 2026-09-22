package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// probeTimeout bounds the handshake. Registering an agent should fail quickly
// when the address is wrong, not sit there.
const probeTimeout = 10 * time.Second

// ProbeFingerprint opens a TLS connection just far enough to read the agent's
// certificate, and returns its fingerprint.
//
// This is the fallback for registering an agent without an invite. It is
// strictly weaker: the fingerprint comes from the same connection it is meant
// to authenticate, so it proves nothing on its own -- anything in the path
// could hand over its own certificate and be pinned instead. What it buys is
// a fingerprint the operator can *compare* against `server fingerprint` on
// the agent, which is the ssh first-connect ritual. An invite carries the
// fingerprint out of band and needs no such comparison.
//
// It returns an empty string, and no error, for a cleartext (http) agent:
// there is no certificate to pin, which is a property of the deployment
// rather than a failure here.
func ProbeFingerprint(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse server url %q: %w", rawURL, err)
	}
	switch u.Scheme {
	case "http", "ws":
		return "", nil
	case "https", "wss":
	default:
		return "", fmt.Errorf("server url %q must be http, https, ws or wss", rawURL)
	}

	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	d := tls.Dialer{Config: &tls.Config{
		// The whole point is to see whatever certificate is presented,
		// including a self-signed one we have no way to verify yet.
		InsecureSkipVerify: true, //nolint:gosec // deliberate: this reads the cert to show it
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", host, err)
	}
	defer conn.Close() //nolint:errcheck // read-only probe

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("the server presented no certificate")
	}
	return Fingerprint(state.PeerCertificates[0].Raw), nil
}
