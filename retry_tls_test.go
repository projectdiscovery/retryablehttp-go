package retryablehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckRecoverableErrorsCertificateErrors(t *testing.T) {
	urlErr := func(err error) error {
		return &url.Error{Op: "Get", URL: "https://127.0.0.1", Err: err}
	}
	verifyErr := func(err error) error {
		return &tls.CertificateVerificationError{Err: err}
	}
	cases := map[string]error{
		"unknown authority":               urlErr(verifyErr(x509.UnknownAuthorityError{})),
		"hostname mismatch":               urlErr(verifyErr(x509.HostnameError{Host: "localhost", Certificate: &x509.Certificate{}})),
		"expired":                         urlErr(verifyErr(x509.CertificateInvalidError{Reason: x509.Expired})),
		"bare unknown authority":          urlErr(x509.UnknownAuthorityError{}),
		"wrapped outside url.Error":       fmt.Errorf("request failed: %w", verifyErr(x509.UnknownAuthorityError{})),
		"verification error, other cause": urlErr(verifyErr(fmt.Errorf("custom verify failed"))),
	}
	for name, err := range cases {
		retry, _ := CheckRecoverableErrors(context.Background(), nil, err)
		require.False(t, retry, name)
	}

	retry, _ := CheckRecoverableErrors(context.Background(), nil, urlErr(&net.OpError{Op: "dial", Err: fmt.Errorf("connection reset")}))
	require.True(t, retry, "a network error stays retryable")
}

// A client that verifies TLS must not retry a certificate it cannot trust.
func TestDoDoesNotRetryCertificateErrors(t *testing.T) {
	var conns int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	srv.StartTLS()
	defer srv.Close()

	trusted := x509.NewCertPool()
	trusted.AddCert(srv.Certificate())

	cases := []struct {
		name    string
		url     string
		rootCAs *x509.CertPool
	}{
		{"unknown authority", srv.URL, nil},
		// The test certificate is for 127.0.0.1 and example.com, not localhost.
		{"hostname mismatch", strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), trusted},
	}
	for _, c := range cases {
		atomic.StoreInt32(&conns, 0)
		client := NewClient(Options{
			HttpClient: &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: c.rootCAs},
			}},
			RetryWaitMin: time.Millisecond,
			RetryWaitMax: time.Millisecond,
			RetryMax:     3,
			Timeout:      5 * time.Second,
		})
		req, err := NewRequest(http.MethodGet, c.url, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err, c.name)
		require.True(t, isCertificateVerificationError(err), "%s: %v", c.name, err)
		require.Equalf(t, int32(1), atomic.LoadInt32(&conns), "%s: certificate error was retried", c.name)
	}
}
