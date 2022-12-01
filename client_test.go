package retryablehttp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go/buggyhttp"
)

// TestRequest parsing methodology
func TestRequest(t *testing.T) {
	// Fails on invalid request
	_, err := NewRequest("GET", "://foo", nil)
	if err == nil {
		t.Fatalf("should error")
	}

	// Works with no request body
	_, err = NewRequest("GET", "http://foo", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Works with request body
	body := bytes.NewReader([]byte("yo"))
	req, err := NewRequest("GET", "/", body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Request allows typical HTTP request forming methods
	req.Header.Set("X-Test", "foo")
	if v, ok := req.Header["X-Test"]; !ok || len(v) != 1 || v[0] != "foo" {
		t.Fatalf("bad headers: %v", req.Header)
	}

	// Sets the Content-Length automatically for LenReaders
	if req.ContentLength != 2 {
		t.Fatalf("bad ContentLength: %d", req.ContentLength)
	}
}

// TestRequestBody reads request body multiple times
// using httputil.DumpRequestOut
func TestRequestBody(t *testing.T) {
	body := bytes.NewReader([]byte("yo"))
	req, err := NewRequest("GET", "https://projectdiscovery.io", body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for i := 0; i < 10; i++ {
		bin, err := httputil.DumpRequestOut(req.Request, true)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		if bytes.Equal([]byte("yo"), bin) {
			t.Errorf("expected %v but got %v", "yo", string(bin))
		}
	}

}

// TestFromRequest cloning from an existing request
func TestFromRequest(t *testing.T) {
	// Works with no request body
	httpReq, err := http.NewRequest("GET", "http://foo", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_, err = FromRequest(httpReq)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Works with request body
	body := bytes.NewReader([]byte("yo"))
	httpReq, err = http.NewRequest("GET", "/", body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	req, err := FromRequest(httpReq)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Preserves headers
	httpReq.Header.Set("X-Test", "foo")
	if v, ok := req.Header["X-Test"]; !ok || len(v) != 1 || v[0] != "foo" {
		t.Fatalf("bad headers: %v", req.Header)
	}

	// Preserves the Content-Length automatically for LenReaders
	if req.ContentLength != 2 {
		t.Fatalf("bad ContentLength: %d", req.ContentLength)
	}
}

// Since normal ways we would generate a Reader have special cases, use a
// custom type here
type custReader struct {
	val string
	pos int
}

func (c *custReader) Read(p []byte) (n int, err error) {
	if c.val == "" {
		c.val = "hello"
	}
	if c.pos >= len(c.val) {
		return 0, io.EOF
	}
	var i int
	for i = 0; i < len(p) && i+c.pos < len(c.val); i++ {
		p[i] = c.val[i+c.pos]
	}
	c.pos += i
	return i, nil
}

// TestClient_Do tests various client body reader versus a generic endpoint
// Expected: Status Code 200 - Limited body size - Zero retries
func TestClient_Do(t *testing.T) {
	testBytes := []byte("hello")
	// Native func
	testClientSuccess_Do(t, testBytes)
	// Native func, different Go type
	testClientSuccess_Do(t, func() (io.Reader, error) {
		return bytes.NewReader(testBytes), nil
	})
	// []byte
	testClientSuccess_Do(t, testBytes)
	// *bytes.Buffer
	testClientSuccess_Do(t, bytes.NewBuffer(testBytes))
	// *bytes.Reader
	testClientSuccess_Do(t, bytes.NewReader(testBytes))
	// io.ReadSeeker
	testClientSuccess_Do(t, strings.NewReader(string(testBytes)))
	// io.Reader
	testClientSuccess_Do(t, &custReader{})
}

// Request to /foo => 200 + valid body
func testClientSuccess_Do(t *testing.T, body interface{}) {
	// Create a request
	req, err := NewRequest("GET", "http://127.0.0.1:8080/foo", body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	req.Header.Set("foo", "bar")

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RetryMax = 50

	// Track the number of times the logging hook was called
	retryCount := -1

	// Create the client. Use short retry windows.
	client := NewClient(options)

	client.RequestLogHook = func(req *http.Request, retryNumber int) {
		retryCount = retryNumber

		dumpBytes, err := httputil.DumpRequestOut(req, false)
		if err != nil {
			t.Fatalf("Dumping requests failed %v", err)
		}

		dumpString := string(dumpBytes)
		if !strings.Contains(dumpString, "GET /foo") {
			t.Fatalf("Bad request dump:\n%s", dumpString)
		}
	}

	// Send the request
	doneCh := make(chan struct{})
	errCh := make(chan error, 1)
	fn := func() {
		defer close(doneCh)
		_, err := client.Do(req)
		if err != nil {
			errCh <- err
		}
	}
	go fn()
	select {
	case <-doneCh:
		// client should have completed
	case <-time.After(time.Second):
		t.Fatalf("successful request should have been completed")
	case error := <-errCh:
		t.Fatalf("err: %v", error)
	}

	expected := 0
	if retryCount != expected {
		t.Fatalf("Retries expected %d but got %d", expected, retryCount)
	}
}

// TestClientRetry_Do tests a generic endpoint that simulates some recoverable failures before responding correctly
// Expected: Some recoverable network failures and after 5 retries the library should be able to get Status Code 200 + Valid Body with various backoff stategies
// Request to /successafter => 5 attempts recoverable + at 6th attempt 200 + valid body
func TestClientRetry_Do(t *testing.T) {
	expectedRetries := 3
	// Create a generic request towards /successAfter passing the number of times before the same request is successful
	req, err := NewRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/successAfter?successAfter=%d", expectedRetries), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RetryMax = 6

	// Create the client. Use short retry windows.
	client := NewClient(options)

	// In this point the retry strategy should kick in until a response is succesful
	_, err = client.Do(req)
	if err != nil {
		// if at the end we get a failure then it's unexpected behavior
		t.Fatalf("err: %v", err)
	}

	// Validate Metrics
	if req.Metrics.Retries != expectedRetries {
		t.Fatalf("err: retries do not match expected %v but got %v", expectedRetries, req.Metrics.Retries)
	}
}

// TestClientRetryWithBody_Do does same as TestClientRetry_Do but with request body and 5 retries
func TestClientRetryWithBody_Do(t *testing.T) {
	expectedRetries := 5
	// Create a generic request towards /successAfter passing the number of times before the same request is successful
	req, err := NewRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/successAfter?successAfter=%d", expectedRetries), "request with body")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RetryMax = 6

	// Create the client. Use short retry windows.
	client := NewClient(options)

	// In this point the retry strategy should kick in until a response is succesful
	_, err = client.Do(req)
	if err != nil {
		// if at the end we get a failure then it's unexpected behavior
		t.Fatalf("err: %v", err)
	}

	// Validate Metrics
	if req.Metrics.Retries != expectedRetries {
		t.Fatalf("err: retries do not match expected %v but got %v", expectedRetries, req.Metrics.Retries)
	}
}

// TestClientEmptyResponse_Do tests a generic endpoint that simulates the server hanging connection immediately (http connection closed by peer)
// Expected: The library should keep on retrying until the final timeout or maximum retries amount
func TestClientEmptyResponse_Do(t *testing.T) {
	// Create a request
	req, err := NewRequest("GET", "http://127.0.0.1:8080/emptyResponse", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RetryMax = 6

	// Create the client. Use short retry windows.
	client := NewClient(options)

	_, err = client.Do(req)
	if err == nil {
		// if at the end we get don't failure then it's unexpected behavior
		t.Fatalf("err: %v", err)
	}
}

// TestClientUnexpectedEOF_Do tests a generic endpoint that simulates the server hanging the connection in the middle of a valid response (connection failure)
// Expected: The library should keep on retrying until the final timeout or maximum retries amount
func TestClientUnexpectedEOF_Do(t *testing.T) {
	// Create a request
	req, err := NewRequest("GET", "http://127.0.0.1:8080/unexpectedEOF", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RetryMax = 6

	// Create the client. Use short retry windows.
	client := NewClient(options)

	_, err = client.Do(req)
	if err == nil {
		// if at the end we get don't failure then it's unexpected behavior
		t.Fatalf("err: %v", err)
	}
}

// TestClientEndlessBody_Do tests a generic endpoint that simulates the server delivering an infinite content body
// Expected: The library should read until a certain limit with return code 200
func TestClientEndlessBody_Do(t *testing.T) {
	// Create a request
	req, err := NewRequest("GET", "http://127.0.0.1:8080/endlessBody", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RespReadLimit = 4096
	options.RetryMax = 6
	options.Timeout = time.Duration(5) * time.Second

	// Create the client. Use short retry windows.
	client := NewClient(options)

	resp, err := client.Do(req)
	if err != nil {
		// if at the end we get a failure then it's unexpected behavior
		t.Fatalf("err: %v", err)
	}

	// Arguably now it's up to the caller to handle the response body
	Discard(req, resp, options.RespReadLimit)
}

// TestClientMessyHeaders_Do tests a generic endpoint that simulates the server sending infinite headers
// Expected: The library should stop reading headers after a certain amount or go into timeout
func TestClientMessyHeaders_Do(t *testing.T) {
	// Create a request
	req, err := NewRequest("GET", "http://127.0.0.1:8080/messyHeaders", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RetryMax = 2

	// Create the client. Use short retry windows.
	client := NewClient(options)

	resp, err := client.Do(req)
	// t.Fatalf("ehhhh")
	if err != nil {
		// if at the end we get a success then it's unexpected behavior
		t.Fatalf("Unexpected fail")
	}

	// Arguably now it's up to the caller to handle the response body
	Discard(req, resp, options.RespReadLimit)
}

// TestClientMessyEncoding_Do tests a generic endpoint that simulates the server sending weird encodings in headers
// Expected: The library should be successful as all strings are treated as runes
func TestClientMessyEncoding_Do(t *testing.T) {
	// Create a request
	req, err := NewRequest("GET", "http://127.0.0.1:8080/messyEncoding", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var options Options
	options.RetryWaitMin = 10 * time.Millisecond
	options.RetryWaitMax = 50 * time.Millisecond
	options.RetryMax = 2

	// Create the client. Use short retry windows.
	client := NewClient(options)

	resp, err := client.Do(req)
	// t.Fatalf("ehhhh")
	if err != nil {
		// if at the end we get a success then it's unexpected behavior
		t.Fatalf("Unexpected fail")
	}

	// Arguably now it's up to the caller to handle the response body
	Discard(req, resp, options.RespReadLimit)
}

func TestMain(m *testing.M) {
	// start buggyhttp
	buggyhttp.Listen(8080)
	defer buggyhttp.Stop()
	m.Run()
}
