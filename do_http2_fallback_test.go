package retryablehttp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// serveHTTP2StatusLine starts a listener that answers every connection with an
// HTTP/2 status line, which makes the HTTP/1.x transport fail with
// `malformed HTTP version "HTTP/2"` and triggers the fallback in Do. It counts
// accepted connections in conns and returns the listener address.
func serveHTTP2StatusLine(t *testing.T, conns *atomic.Int32) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			answerHTTP2StatusLine(c)
		}
	}()

	return ln.Addr().String()
}

// answerHTTP2StatusLine reads a request from c, replies with an HTTP/2 status
// line, and closes c.
func answerHTTP2StatusLine(c net.Conn) {
	_, _ = c.Read(make([]byte, 4096))
	_, _ = c.Write([]byte("HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n"))
	_ = c.Close()
}

// http2StatusLineOnce answers the first accepted connection with an HTTP/2
// status line and hands later connections to the server.
type http2StatusLineOnce struct {
	net.Listener
	answered atomic.Bool
}

func (l *http2StatusLineOnce) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil || !l.answered.CompareAndSwap(false, true) {
			return c, err
		}
		answerHTTP2StatusLine(c)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestDoHTTP2FallbackUsesCallerClient verifies that the HTTP/2 fallback in Do
// goes through the caller's http.Client (here: its proxy) instead of dialing
// the target directly.
func TestDoHTTP2FallbackUsesCallerClient(t *testing.T) {
	tests := []struct {
		name      string
		transport func(proxy *url.URL) http.RoundTripper
	}{
		{
			name: "http.Transport",
			transport: func(proxy *url.URL) http.RoundTripper {
				return &http.Transport{Proxy: http.ProxyURL(proxy)}
			},
		},
		{
			name: "custom RoundTripper",
			transport: func(proxy *url.URL) http.RoundTripper {
				base := &http.Transport{Proxy: http.ProxyURL(proxy)}
				return roundTripperFunc(base.RoundTrip)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var proxyConns, targetConns atomic.Int32
			proxy, err := url.Parse("http://" + serveHTTP2StatusLine(t, &proxyConns))
			require.NoError(t, err)
			target := "http://" + serveHTTP2StatusLine(t, &targetConns) + "/"

			hc := &http.Client{Transport: tt.transport(proxy)}
			client := NewWithHTTPClient(hc, Options{RetryMax: 0})
			require.NotNil(t, client)

			req, err := NewRequest(http.MethodGet, target, nil)
			require.NoError(t, err)

			_, err = client.Do(req)
			require.ErrorContains(t, err, `malformed HTTP version "HTTP/2"`)

			require.Zero(t, targetConns.Load(), "fallback dialed the target directly")
			require.EqualValues(t, 2, proxyConns.Load(), "first attempt and fallback should both use the proxy")
		})
	}
}

// TestDoHTTP2FallbackKeepsDigestAuth verifies that the HTTP/2 fallback in Do
// answers a digest challenge, as the first attempt does.
func TestDoHTTP2FallbackKeepsDigestAuth(t *testing.T) {
	tests := []struct {
		name     string
		fallback bool
	}{
		{name: "first attempt"},
		{name: "fallback", fallback: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.Header.Get("Authorization"), `Digest username="u"`) {
					w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n", qop="auth"`)
					w.WriteHeader(http.StatusUnauthorized)
				}
			}))
			if tt.fallback {
				ts.Listener = &http2StatusLineOnce{Listener: ts.Listener}
			}
			ts.Start()
			t.Cleanup(ts.Close)

			client := NewClient(Options{RetryMax: 0})
			require.NotNil(t, client)

			req, err := NewRequest(http.MethodGet, ts.URL, nil)
			require.NoError(t, err)
			req.Auth = &Auth{Type: DigestAuth, Username: "u", Password: "p"}

			resp, err := client.Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// TestNewClientHTTP2FallbackKeepsCallerSettings verifies that HTTPClient2
// keeps the caller's client-level settings.
func TestNewClientHTTP2FallbackKeepsCallerSettings(t *testing.T) {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	errRedirect := errors.New("redirect")
	hc := &http.Client{
		Transport:     &http.Transport{},
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}

	client := NewWithHTTPClient(hc, Options{})
	require.NotNil(t, client)
	require.Same(t, jar, client.HTTPClient2.Jar, "caller's cookie jar must be kept")
	require.NotNil(t, client.HTTPClient2.CheckRedirect, "caller's redirect policy must be kept")
	require.ErrorIs(t, client.HTTPClient2.CheckRedirect(nil, nil), errRedirect)
}

// TestNewClientHTTP2FallbackNegotiatesHTTP2 verifies that HTTPClient2 speaks
// HTTP/2 through a copy of the caller's transport, while HTTPClient keeps the
// caller's transport as configured.
func TestNewClientHTTP2FallbackNegotiatesHTTP2(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)

	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	// A custom TLS config disables HTTP/2 unless it is forced.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	client := NewWithHTTPClient(hc, Options{})
	require.NotNil(t, client)

	for _, tt := range []struct {
		name       string
		client     *http.Client
		protoMajor int
	}{
		{"HTTPClient", client.HTTPClient, 1},
		{"HTTPClient2", client.HTTPClient2, 2},
	} {
		resp, err := tt.client.Get(ts.URL)
		require.NoError(t, err, tt.name)
		_ = resp.Body.Close()
		require.Equal(t, tt.protoMajor, resp.ProtoMajor, tt.name)
	}
}
