package retryablehttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var digestTestAuth = &Auth{Type: DigestAuth, Username: "u", Password: "p"}

const digestTestChallenge = `Digest realm="r", nonce="n", qop="auth"`

// requireDigest challenges requests without a valid Authorization header for
// digestTestAuth and passes the others to next. Like a real server, it checks
// the response hash against the method and request-target it received.
func requireDigest(next http.HandlerFunc) http.HandlerFunc {
	challenge, _ := findDigestChallenge(http.Header{"Www-Authenticate": {digestTestChallenge}})
	return func(w http.ResponseWriter, r *http.Request) {
		_, got, _ := cutChallenge(r.Header.Get("Authorization"))
		_, want, _ := cutChallenge(challenge.authorization(digestTestAuth, r.Method, r.RequestURI, nil, got["cnonce"]))
		if got["response"] != want["response"] {
			w.Header().Set("WWW-Authenticate", digestTestChallenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func TestDoDigestAuthKeepsCallerRequest(t *testing.T) {
	var gotHeader, gotBody atomic.Value
	srv := httptest.NewServer(requireDigest(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotHeader.Store(r.Header.Get("X-Custom"))
		gotBody.Store(string(body))
	}))
	defer srv.Close()

	client := NewClient(Options{RetryMax: 0})
	req, err := NewRequest(http.MethodPost, srv.URL+"/a/b?x=1&y=2", "payload")
	require.NoError(t, err)
	req.Header.Set("X-Custom", "1")
	req.Auth = digestTestAuth

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "1", gotHeader.Load(), "authenticated request lost the caller's header")
	require.Equal(t, "payload", gotBody.Load(), "authenticated request lost the body")
	require.Empty(t, req.Header.Get("Authorization"), "Do changed the caller's request")
}

// TestDoDigestAuthResendsLargeBody covers a server that challenges a body too
// large for net/http to drain, so it stops reading the body early. The request
// is sent twice, as a retry would send it, to check that req.Body stays whole.
func TestDoDigestAuthResendsLargeBody(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 8<<20)
	srv := httptest.NewServer(requireDigest(func(w http.ResponseWriter, r *http.Request) {
		if body, _ := io.ReadAll(r.Body); !bytes.Equal(body, payload) {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	// Each request gets its own copy because the reusable body reader writes
	// into the slice it wraps.
	tests := map[string]func() (*Request, error){
		"NewRequest": func() (*Request, error) {
			return NewRequest(http.MethodPost, srv.URL, bytes.Clone(payload))
		},
		"SetBody": func() (*Request, error) {
			req, err := NewRequest(http.MethodPost, srv.URL, nil)
			if err != nil {
				return nil, err
			}
			return req, req.SetBody(bytes.Clone(payload))
		},
	}
	for name, newRequest := range tests {
		t.Run(name, func(t *testing.T) {
			req, err := newRequest()
			require.NoError(t, err)
			req.Auth = digestTestAuth

			client := NewClient(Options{RetryMax: 0})
			for range 2 {
				resp, err := client.Do(req)
				require.NoError(t, err)
				_ = resp.Body.Close()

				require.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	}
}

func TestDoDigestAuthSendsBodyWithoutGetBody(t *testing.T) {
	var gotBody atomic.Value
	srv := httptest.NewServer(requireDigest(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody.Store(string(body))
	}))
	defer srv.Close()

	req, err := NewRequest(http.MethodPost, srv.URL, nil)
	require.NoError(t, err)
	req.Body = io.NopCloser(strings.NewReader("payload"))
	req.ContentLength = int64(len("payload"))
	req.Auth = digestTestAuth

	resp, err := NewClient(Options{RetryMax: 0}).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "payload", gotBody.Load())
}

func TestDoDigestAuthRecordsTrace(t *testing.T) {
	srv := httptest.NewServer(requireDigest(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	client := NewClient(Options{RetryMax: 0, Trace: true})
	req, err := NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Auth = digestTestAuth

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, req.TraceInfo)
	require.False(t, req.TraceInfo.GotConn.Time.IsZero(), "GotConn was not traced")
	require.False(t, req.TraceInfo.WroteRequest.Time.IsZero(), "WroteRequest was not traced")
}

func TestDoDigestAuthHonorsRequestContext(t *testing.T) {
	// The handler outlives the request deadline by far, so only cancellation
	// can make Do return quickly.
	srv := httptest.NewServer(requireDigest(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client := NewClient(Options{RetryMax: 0})
	req, err := NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Auth = digestTestAuth

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if resp != nil {
		_ = resp.Body.Close()
	}

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, elapsed, time.Second, "Do ignored the request context")
}

// TestDoDigestAuthReturnsUnansweredChallenge verifies that a 401 without a
// supported Digest challenge reaches the caller after a single request.
func TestDoDigestAuthReturnsUnansweredChallenge(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := NewClient(Options{RetryMax: 0})
	req, err := NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Auth = digestTestAuth

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.EqualValues(t, 1, hits.Load())
}
