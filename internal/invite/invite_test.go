package invite_test

import (
	"strings"
	"testing"

	"github.com/wargasipil/san_tunnels/internal/invite"
)

func TestRoundTrip(t *testing.T) {
	want := invite.Invite{
		URL:            "https://box-01.example:8443",
		Token:          "s3cret",
		TLSFingerprint: "SHA256:uLryclk7t22aMWQciVWkXfgkz8YgPh5RhLuFVeAAoBQ",
		HostKey:        "SHA256:PSVUi/jrVcmeHQVPIzbIZ5+x8PHyIZYH5J8NalKoGIc",
		User:           "deploy",
	}

	blob, err := invite.Encode(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.HasPrefix(blob, invite.Prefix) {
		t.Fatalf("blob %q does not start with %q", blob, invite.Prefix)
	}

	got, err := invite.Decode(blob)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Fatalf("round trip gave %+v, want %+v", got, want)
	}
}

// Pasting picks up whitespace and newlines; that must not break it.
func TestDecodeTolerantOfPaste(t *testing.T) {
	blob, err := invite.Encode(invite.Invite{URL: "https://example:8443"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	for _, s := range []string{blob, " " + blob, blob + "\n", "\t" + blob + "  \r\n"} {
		got, derr := invite.Decode(s)
		if derr != nil {
			t.Fatalf("Decode(%q): %v", s, derr)
		}
		if got.URL != "https://example:8443" {
			t.Fatalf("got url %q", got.URL)
		}
	}
}

func TestDecodeRejectsJunk(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"no prefix":    "aGVsbG8",
		"not base64":   invite.Prefix + "!!!!",
		"not json":     invite.Prefix + "aGVsbG8",
		"no url":       invite.Prefix + "e30", // {}
		"another tool": "ghp_0123456789",
	}
	for name, s := range cases {
		if _, err := invite.Decode(s); err == nil {
			t.Errorf("%s: Decode(%q) succeeded, want an error", name, s)
		}
	}
}

// An invite with no URL is useless, and saying so at encode time beats
// handing someone a token that cannot work.
func TestEncodeRequiresURL(t *testing.T) {
	if _, err := invite.Encode(invite.Invite{Token: "s3cret"}); err == nil {
		t.Fatal("encoded an invite with no url")
	}
}

// Redact exists so an invite can be logged. It must not leak the token, and
// must not mutate the caller's copy.
func TestRedact(t *testing.T) {
	orig := invite.Invite{URL: "https://example:8443", Token: "s3cret"}
	red := invite.Redact(orig)

	if strings.Contains(red.Token, "s3cret") {
		t.Fatalf("redacted token still reads %q", red.Token)
	}
	if orig.Token != "s3cret" {
		t.Fatal("Redact mutated the original")
	}
	if red.URL != orig.URL {
		t.Fatal("Redact should leave everything but the token alone")
	}
}
