package retryablehttp

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDisableHTTP2Fallback verifies that when DisableHTTP2Fallback is set,
// the client does not fall back to HTTPClient2 on HTTP/1.x transport errors.
func TestDisableHTTP2Fallback(t *testing.T) {
	// Track which client was used
	http2ClientUsed := false

	options := Options{
		RetryWaitMin:         10 * time.Millisecond,
		RetryWaitMax:         50 * time.Millisecond,
		RetryMax:             0, // no retries, we just want to test the fallback behavior
		Timeout:              5 * time.Second,
		DisableHTTP2Fallback: true,
	}

	client := NewClient(options)
	require.NotNil(t, client)

	// Replace HTTPClient2 with a tracking transport
	client.HTTPClient2 = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			http2ClientUsed = true
			return nil, nil
		}),
		Timeout: 5 * time.Second,
	}

	// Make a request - even if it fails, we just want to ensure HTTPClient2 was NOT used
	req, err := NewRequest("GET", "http://127.0.0.1:8080/foo", nil)
	require.NoError(t, err)

	_, _ = client.Do(req)

	require.False(t, http2ClientUsed, "HTTPClient2 should not be used when DisableHTTP2Fallback is true")
}

// TestHTTP2FallbackEnabledByDefault verifies that the fallback to HTTPClient2
// is enabled by default (DisableHTTP2Fallback defaults to false).
func TestHTTP2FallbackEnabledByDefault(t *testing.T) {
	options := Options{
		RetryWaitMin: 10 * time.Millisecond,
		RetryWaitMax: 50 * time.Millisecond,
		RetryMax:     0,
		Timeout:      5 * time.Second,
	}

	client := NewClient(options)
	require.NotNil(t, client)

	// DisableHTTP2Fallback should default to false
	require.False(t, client.options.DisableHTTP2Fallback, "DisableHTTP2Fallback should be false by default")
}

// roundTripperFunc is a helper type to use a function as an http.RoundTripper
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
