package retryablehttp

import (
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDisableHTTPFallbackSkipsHTTP2Client(t *testing.T) {
	// Force a transport error that normally triggers the internal HTTP/2 fallback.
	malformed := errors.New("net/http: HTTP/1.x transport connection broken: malformed HTTP version \"HTTP/2\"")

	var fallbackCalls int32
	fallback := &http.Client{Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		atomic.AddInt32(&fallbackCalls, 1)
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})}

	client := NewClient(Options{
		DisableHTTPFallback: true,
		HttpClient: &http.Client{Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, malformed
		})},
	})
	client.HTTPClient2 = fallback

	_, _ = client.Do(&Request{Request: &http.Request{Method: "GET", URL: &url.URL{Scheme: "http", Host: "example.com"}, Header: make(http.Header)}})
	if got := atomic.LoadInt32(&fallbackCalls); got != 0 {
		t.Fatalf("expected fallback client not to be called, got %d", got)
	}
}
