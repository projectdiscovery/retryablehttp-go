package retryablehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// alwaysRetry forces the retry loop to keep going so the loop exit conditions
// (overall timeout / request cancellation) can be exercised in isolation from
// any status-code policy.
func alwaysRetry(_ context.Context, _ *http.Response, _ error) (bool, error) {
	return true, nil
}

// TestDoMainTimeoutStopsRetrying verifies that once the overall Options.Timeout
// elapses the retry loop stops instead of breaking only the inner select and
// storming through the remaining retries with no backoff.
func TestDoMainTimeoutStopsRetrying(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := Options{
		RetryWaitMin: 300 * time.Millisecond,
		RetryWaitMax: 300 * time.Millisecond,
		Timeout:      100 * time.Millisecond,
		RetryMax:     5,
		CheckRetry:   alwaysRetry,
	}
	client := NewClient(opts)

	req, err := NewRequest("GET", srv.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if resp != nil {
		_ = resp.Body.Close()
	}

	require.Error(t, err, "expected an error once the overall timeout elapsed")
	// the timeout (100ms) fires during the first backoff (300ms), so exactly one
	// request should have been sent. Without the fix all RetryMax+1 requests run.
	require.LessOrEqualf(t, atomic.LoadInt32(&hits), int32(2),
		"retry storm after timeout: %d requests sent", atomic.LoadInt32(&hits))
	require.Lessf(t, elapsed, 2*time.Second, "did not stop promptly at timeout: %v", elapsed)
}

// TestDoRequestCancelDuringBackoffReturnsPromptly verifies that cancelling the
// request context while waiting on the backoff returns immediately with the
// context error (the path whose backoff timer is now released instead of left
// to fire after the full RetryWaitMax).
func TestDoRequestCancelDuringBackoffReturnsPromptly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := Options{
		RetryWaitMin: 30 * time.Second,
		RetryWaitMax: 30 * time.Second,
		Timeout:      60 * time.Second,
		RetryMax:     5,
		CheckRetry:   alwaysRetry,
	}
	client := NewClient(opts)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := NewRequestWithContext(ctx, "GET", srv.URL, nil)
	require.NoError(t, err)

	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		done <- result{resp, err}
	}()

	// let the first request complete and the loop enter the long backoff
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case res := <-done:
		if res.resp != nil {
			_ = res.resp.Body.Close()
		}
		require.Truef(t, errors.Is(res.err, context.Canceled),
			"expected context.Canceled, got %v", res.err)
		require.Lessf(t, time.Since(start), 5*time.Second,
			"cancel did not unblock backoff promptly: %v", time.Since(start))
	case <-time.After(10 * time.Second):
		t.Fatal("Do did not return after request context was cancelled")
	}
}

func TestDoMainTimeoutError(t *testing.T) {
	transportErr := errors.New("connection failed")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	for _, tt := range []struct {
		name      string
		transport bool
		handler   bool
		exhaust   bool
	}{
		{name: "response/default"},
		{name: "response/handler", handler: true},
		{name: "transport/default", transport: true},
		{name: "transport/handler", transport: true, handler: true},
		{name: "exhausted/default", transport: true, exhaust: true},
		{name: "exhausted/handler", transport: true, handler: true, exhaust: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{
				RetryWaitMin: time.Second,
				RetryWaitMax: time.Second,
				Timeout:      50 * time.Millisecond,
				RetryMax:     5,
				CheckRetry:   alwaysRetry,
			}
			if tt.transport {
				opts.HttpClient = &http.Client{Transport: timeoutErrorTransport{err: transportErr}}
			}
			if tt.exhaust {
				opts.Timeout = 0
				opts.RetryMax = 0
			}
			client := NewClient(opts)
			defer client.HTTPClient.CloseIdleConnections()
			defer client.HTTPClient2.CloseIdleConnections()

			handlerCalled := false
			var handlerErr error
			if tt.handler {
				client.ErrorHandler = func(resp *http.Response, err error, _ int) (*http.Response, error) {
					handlerCalled = true
					handlerErr = err
					return PassthroughErrorHandler(resp, err, 0)
				}
			}

			req, err := NewRequest(http.MethodGet, srv.URL, nil)
			require.NoError(t, err)
			attempts := 0
			client.RequestLogHook = func(_ *http.Request, _ int) {
				attempts++
			}
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			wantErr := error(context.DeadlineExceeded)
			if tt.exhaust {
				wantErr = transportErr
			}
			require.ErrorIs(t, err, wantErr)
			require.Equal(t, 1, attempts)
			if tt.handler {
				require.True(t, handlerCalled)
				require.ErrorIs(t, handlerErr, wantErr)
			}
		})
	}
}

type timeoutErrorTransport struct {
	err error
}

func (rt timeoutErrorTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, rt.err
}
