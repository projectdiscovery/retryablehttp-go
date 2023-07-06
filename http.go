package retryablehttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

// DisableZTLSFallback disables use of ztls when there is error in tls handshake
// can also be disabled by setting DISABLE_ZTLS_FALLBACK env variable to true
var DisableZTLSFallback = false

// DefaultHostSprayingTransport returns a new http.Transport with similar default values to
// http.DefaultTransport, but with idle connections and keepalives disabled.
func DefaultHostSprayingTransport() *http.Transport {
	transport := DefaultReusePooledTransport()
	transport.DisableKeepAlives = true
	transport.MaxIdleConnsPerHost = -1
	return transport
}

// DefaultReusePooledTransport returns a new http.Transport with similar default
// values to http.DefaultTransport. Do not use this for transient transports as
// it can leak file descriptors over time. Only use this for transports that
// will be re-used for the same host(s).
func DefaultReusePooledTransport() *http.Transport {
	dialerConfig := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            dialerConfig.DialContext,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxIdleConnsPerHost:    100,
		MaxResponseHeaderBytes: 4096, // net/http default is 10Mb
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient, // Renegotiation is not supported in TLS 1.3 as per docs
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	transport.DialTLSContext = GetZtlsFallbackDialTLSContext(dialerConfig, transport.TLSClientConfig)
	return transport
}

// GetZtlsFallbackDialTLSContext returns a DialTLSContext function that will fallback to ztls if there is error in tls handshake
func GetZtlsFallbackDialTLSContext(dialer *net.Dialer, tlsconfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		tlsConn, err := tls.DialWithDialer(dialer, network, addr, tlsconfig)
		if err == nil || DisableZTLSFallback {
			// return if no error or ztls fallback is disabled
			return tlsConn, err
		}
		// skip ztls fallback for timeout errors
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return tlsConn, err
		}
		// fallback to ztls
		return ztls.DialWithDialer(dialer, network, addr, &ztls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       ztls.ChromeCiphers, // always fallback with chrome ciphers
		})
	}
}

// DefaultClient returns a new http.Client with similar default values to
// http.Client, but with a non-shared Transport, idle connections disabled, and
// keepalives disabled.
func DefaultClient() *http.Client {
	return &http.Client{
		Transport: DefaultHostSprayingTransport(),
	}
}

// DefaultPooledClient returns a new http.Client with similar default values to
// http.Client, but with a shared Transport. Do not use this function for
// transient clients as it can leak file descriptors over time. Only use this
// for clients that will be re-used for the same host(s).
func DefaultPooledClient() *http.Client {
	return &http.Client{
		Transport: DefaultReusePooledTransport(),
	}
}

func init() {
	value := os.Getenv("DISABLE_ZTLS_FALLBACK")
	if strings.EqualFold(value, "true") {
		DisableZTLSFallback = true
	}
}
