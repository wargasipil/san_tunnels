package agent

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/wargasipil/san_tunnels/gen/san/tunnels/v1/tunnelsv1connect"
	"github.com/wargasipil/san_tunnels/internal/wsconn"
)

// ServeOptions configures the agent's HTTP server.
type ServeOptions struct {
	Listen  string
	Token   string
	TLSCert string
	TLSKey  string
	// TLSAuto generates and persists a self-signed certificate at TLSCert and
	// TLSKey when they do not exist yet. Clients pin it by fingerprint, the
	// same way they already pin the SSH host key, so this needs no CA and no
	// ACME challenge -- which matters because agents often have no public DNS
	// name to satisfy one with.
	TLSAuto bool
	// TLSHosts are extra SAN entries for a generated certificate. Loopback and
	// this machine's hostname are always included.
	TLSHosts []string
	// H2C serves cleartext HTTP/2. Only safe behind an L4 proxy that
	// terminates TLS, or on a trusted network.
	H2C bool
	// WSOrigins are the browser origins allowed to open a WebSocket tunnel.
	WSOrigins []string
	Service   *Service
	Log       *slog.Logger
}

// HandlerOptions configures the agent's HTTP handler.
type HandlerOptions struct {
	Service   *Service
	Token     string
	H2C       bool
	WSOrigins []string
	Log       *slog.Logger
}

// Handler builds the agent's HTTP handler, middleware included.
//
// Two doors onto the same Service: Connect over HTTP/2, and WebSocket over
// HTTP/1.1 for paths that cannot carry a full-duplex h2 stream. They diverge
// only in how they produce a net.Conn; Service.Handle is common to both.
//
// Ordering matters twice over. h2c must be outermost so the protocol check
// runs after the cleartext upgrade, otherwise every h2c request is rejected as
// HTTP/1.1. And the token check must sit inside the protocol check but outside
// the mux, so both doors are behind the same bearer token.
func Handler(o HandlerOptions) http.Handler {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}

	mux := http.NewServeMux()
	path, h := tunnelsv1connect.NewTunnelServiceHandler(o.Service)
	mux.Handle(path, h)

	ws := WSOptions{Service: o.Service, Origins: o.WSOrigins, Log: log}
	mux.Handle(wsconn.Path, wsHandler(ws))
	mux.Handle(wsconn.PingPath, wsPingHandler(ws))

	var handler http.Handler = mux
	handler = requireToken(o.Token, handler, log)
	handler = requireHTTP2(handler, log)
	if o.H2C {
		handler = h2c.NewHandler(handler, &http2.Server{})
	}
	return handler
}

// requireHTTP2 turns a silently hanging session into a loud rejection.
//
// A proxy that speaks HTTP/2 to the client and HTTP/1.1 to us must buffer the
// whole request body before forwarding it, and an interactive client never
// closes its request body -- so without this check the first `open` message
// simply never arrives and the terminal hangs with no error anywhere.
//
// The WebSocket paths are exempt, and must be: an Upgrade handshake is
// HTTP/1.1 by definition (RFC 6455), and Go's server does not implement the
// HTTP/2 extended CONNECT of RFC 8441, so /ws arrives over 1.1 or not at all.
// Rejecting it here would close the very door this opens.
func requireHTTP2(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, wsconn.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if r.ProtoMajor < 2 {
			msg := fmt.Sprintf(
				"san_tunnels requires HTTP/2, but this request arrived as %s. "+
					"Something in front of the agent is downgrading the connection, "+
					"which makes full-duplex streams impossible.", r.Proto)
			log.Error("rejected non-HTTP/2 request", "proto", r.Proto, "remote", r.RemoteAddr)
			http.Error(w, msg, http.StatusHTTPVersionNotSupported)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireToken checks the transport bearer token. This decides who may open a
// tunnel at all; SSH key auth separately decides who gets a shell.
func requireToken(token string, next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			log.Warn("rejected request with bad token", "remote", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Serve runs the agent until ctx is cancelled.
func Serve(ctx context.Context, o ServeOptions) error {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	if o.Service == nil {
		return errors.New("a service is required")
	}
	useTLS := o.TLSCert != "" && o.TLSKey != ""
	if useTLS && o.H2C {
		return errors.New("--h2c and --tls-cert are mutually exclusive")
	}
	if !useTLS && !o.H2C {
		return errors.New("no transport configured: pass --tls-cert and --tls-key, --tls-auto for a self-signed certificate, or --h2c to serve cleartext behind an L4 proxy")
	}

	// A generated certificate is loaded up front so its fingerprint can be
	// logged at startup: that string is what a client pins, and it is useless
	// if an operator has to go digging for it.
	var generated *tls.Certificate
	if useTLS && o.TLSAuto {
		cert, err := LoadOrCreateTLSCert(o.TLSCert, o.TLSKey, o.TLSHosts)
		if err != nil {
			return err
		}
		fp, err := LeafFingerprint(cert)
		if err != nil {
			return err
		}
		generated = cert
		log.Info("tls certificate ready",
			"cert", o.TLSCert, "fingerprint", fp,
			"hint", "pin this as tls_fingerprint in the client config")
	}

	srv := &http.Server{
		Addr: o.Listen,
		Handler: Handler(HandlerOptions{
			Service:   o.Service,
			Token:     o.Token,
			H2C:       o.H2C,
			WSOrigins: o.WSOrigins,
			Log:       log,
		}),
		// Deliberately no ReadTimeout or WriteTimeout: tunnelled streams are
		// long-lived, and either would sever a working session mid-use.
		ReadHeaderTimeout: 20 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		if useTLS {
			log.Info("agent listening", "addr", o.Listen, "transport", "https/h2")
			if generated != nil {
				// Serve the already-loaded pair rather than re-reading the
				// files, so startup cannot race a concurrent regeneration.
				srv.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{*generated},
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{"h2", "http/1.1"},
				}
				errc <- srv.ListenAndServeTLS("", "")
				return
			}
			errc <- srv.ListenAndServeTLS(o.TLSCert, o.TLSKey)
			return
		}
		log.Info("agent listening", "addr", o.Listen, "transport", "h2c (cleartext)")
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		log.Info("shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}
