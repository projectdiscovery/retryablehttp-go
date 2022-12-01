package retryablehttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"

	readerutil "github.com/projectdiscovery/utils/reader"
)

// Request wraps the metadata needed to create HTTP requests.
// Request is not threadsafe. A request cannot be used by multiple goroutines
// concurrently.
type Request struct {
	// Embed an HTTP request directly. This makes a *Request act exactly
	// like an *http.Request so that all meta methods are supported.
	*http.Request

	// Metrics contains the metrics for the request.
	Metrics Metrics

	Auth *Auth
}

// Metrics contains the metrics about each request
type Metrics struct {
	// Failures is the number of failed requests
	Failures int
	// Retries is the number of retries for the request
	Retries int
	// DrainErrors is number of errors occured in draining response body
	DrainErrors int
}

// Auth specific information
type Auth struct {
	Type     AuthType
	Username string
	Password string
}

type AuthType uint8

const (
	DigestAuth AuthType = iota
)

// RequestLogHook allows a function to run before each retry. The HTTP
// request which will be made, and the retry number (0 for the initial
// request) are available to users. The internal logger is exposed to
// consumers.
type RequestLogHook func(*http.Request, int)

// ResponseLogHook is like RequestLogHook, but allows running a function
// on each HTTP response. This function will be invoked at the end of
// every HTTP request executed, regardless of whether a subsequent retry
// needs to be performed or not. If the response body is read or closed
// from this method, this will affect the response returned from Do().
type ResponseLogHook func(*http.Response)

// ErrorHandler is called if retries are expired, containing the last status
// from the http library. If not specified, default behavior for the library is
// to close the body and return an error indicating how many tries were
// attempted. If overriding this, be sure to close the body if needed.
type ErrorHandler func(resp *http.Response, err error, numTries int) (*http.Response, error)

// NewRequest creates a new wrapped request.
func NewRequest(method, url string, body interface{}) (*Request, error) {
	bodyReader, contentLength, err := getReusableBodyandContentLength(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// content-length and body should be assigned only
	// if request has body
	if bodyReader != nil {
		httpReq.ContentLength = contentLength
		httpReq.Body = bodyReader
	}

	return &Request{httpReq, Metrics{}, nil}, nil
}

// NewRequestWithContext creates a new wrapped request with context
func NewRequestWithContext(ctx context.Context, method, url string, body interface{}) (*Request, error) {
	bodyReader, contentLength, err := getReusableBodyandContentLength(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	// content-length and body should be assigned only
	// if request has body
	if bodyReader != nil {
		httpReq.ContentLength = contentLength
		httpReq.Body = bodyReader
	}

	return &Request{httpReq, Metrics{}, nil}, nil
}

// WithContext returns wrapped Request with a shallow copy of underlying *http.Request
// with its context changed to ctx. The provided ctx must be non-nil.
func (r *Request) WithContext(ctx context.Context) *Request {
	r.Request = r.Request.WithContext(ctx)
	return r
}

// FromRequest wraps an http.Request in a retryablehttp.Request
func FromRequest(r *http.Request) (*Request, error) {
	req := Request{
		Request: r,
		Metrics: Metrics{},
		Auth:    nil,
	}

	if r.Body != nil {
		body, err := readerutil.NewReusableReadCloser(r.Body)
		if err != nil {
			return nil, err
		}
		r.Body = body
		req.ContentLength, err = getLength(body)
		if err != nil {
			return nil, err
		}
	}

	return &req, nil
}

// FromRequestWithTrace wraps an http.Request in a retryablehttp.Request with trace enabled
func FromRequestWithTrace(r *http.Request) (*Request, error) {
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Fprintf(os.Stderr, "Got connection\tReused: %v\tWas Idle: %v\tIdle Time: %v\n", connInfo.Reused, connInfo.WasIdle, connInfo.IdleTime)
		},
		ConnectStart: func(network, addr string) {
			fmt.Fprintf(os.Stderr, "Dial start\tnetwork: %s\taddress: %s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Fprintf(os.Stderr, "Dial done\tnetwork: %s\taddress: %s\terr: %v\n", network, addr, err)
		},
		GotFirstResponseByte: func() {
			fmt.Fprintf(os.Stderr, "Got response's first byte\n")
		},
		WroteHeaders: func() {
			fmt.Fprintf(os.Stderr, "Wrote request headers\n")
		},
		WroteRequest: func(wr httptrace.WroteRequestInfo) {
			fmt.Fprintf(os.Stderr, "Wrote request, err: %v\n", wr.Err)
		},
	}

	r = r.WithContext(httptrace.WithClientTrace(r.Context(), trace))

	return FromRequest(r)
}

// BodyBytes allows accessing the request body. It is an analogue to
// http.Request's Body variable, but it returns a copy of the underlying data
// rather than consuming it.
//
// This function is not thread-safe; do not call it at the same time as another
// call, or at the same time this request is being used with Client.Do.
func (r *Request) BodyBytes() ([]byte, error) {
	if r.Request.Body == nil {
		return nil, nil
	}
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getReusableBodyandContentLength(rawBody interface{}) (*readerutil.ReusableReadCloser, int64, error) {

	var bodyReader *readerutil.ReusableReadCloser
	var contentLength int64

	if rawBody != nil {
		switch body := rawBody.(type) {
		// If they gave us a function already, great! Use it.
		case readerutil.ReusableReadCloser:
			bodyReader = &body
		case *readerutil.ReusableReadCloser:
			bodyReader = body
		// If they gave us a reader function read it and get reusablereader
		case func() (io.Reader, error):
			tmp, err := body()
			if err != nil {
				return nil, 0, err
			}
			bodyReader, err = readerutil.NewReusableReadCloser(tmp)
			if err != nil {
				return nil, 0, err
			}
		// If ReusableReadCloser is not given try to create new from it
		// if not possible return error
		default:
			var err error
			bodyReader, err = readerutil.NewReusableReadCloser(body)
			if err != nil {
				return nil, 0, err
			}
		}
	}

	if bodyReader != nil {
		var err error
		contentLength, err = getLength(bodyReader)
		if err != nil {
			return nil, 0, err
		}
	}

	return bodyReader, contentLength, nil
}

func (request *Request) hasAuth() bool {
	return request.Auth != nil
}
