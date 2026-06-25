// Package buggyhttp is a webserver affected by any kind of network issues
package buggyhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultSuccessAfterThreshold = 10
)

// SO MANY BYTES
func endlessBody(w http.ResponseWriter, req *http.Request) {
	for {
		if _, err := fmt.Fprintf(w, "boo"); err != nil {
			// this allows to quit the go routine when the client disconnects
			break
		}
	}
}

// SO MANY SECONDS
func endlessWaitTime(w http.ResponseWriter, req *http.Request) {
	for {
		if _, err := fmt.Fprintf(w, ""); err != nil {
			// this allows to quit the go routine when the client disconnects
			break
		}
	}
}

// SO MANY HEADERS
func messyHeaders(w http.ResponseWriter, req *http.Request) {
	for {
		if _, err := fmt.Fprintf(w, "%v: %v\n", SecureRandomAlphaString(10), SecureRandomAlphaString(255)); err != nil {
			// this allows to quit the go routine when the client disconnects
			break
		}
	}
}

// SO MANY ENCODINGS
func messyEncoding(w http.ResponseWriter, req *http.Request) {
	var soManyEncodings = []string{
		"Foo: bar\r\n",
		"X-Foo: bar\r\n",
		"Foo: a space\r\n",
		"A space: foo\r\n",    // space in header
		"foo\xffbar: foo\r\n", // binary in header
		"foo\x00bar: foo\r\n", // binary in header
		"Foo: " + strings.Repeat("x", 1<<21) + "\r\n", // header too large
		// Spaces between the header key and colon are not allowed.
		// See RFC 7230, Section 3.2.4.
		"Foo : bar\r\n",
		"Foo\t: bar\r\n",

		"foo: foo foo\r\n",    // LWS space is okay
		"foo: foo\tfoo\r\n",   // LWS tab is okay
		"foo: foo\x00foo\r\n", // CTL 0x00 in value is bad
		"foo: foo\x7ffoo\r\n", // CTL 0x7f in value is bad
		"foo: foo\xfffoo\r\n", // non-ASCII high octets in value are fine
	}

	for _, oneencodingfrommany := range soManyEncodings {
		_, _ = fmt.Fprint(w, oneencodingfrommany)
	}
}

// SO MANY DELAYS
func superSlow(w http.ResponseWriter, req *http.Request) {
	// echoes out all requests headers (just because we are lazy)
	z := w.(http.Flusher)
	for name, headers := range req.Header {
		for _, h := range headers {
			_, _ = fmt.Fprintf(w, "%v: %v\n", name, h)
			z.Flush()
			time.Sleep(250 * time.Millisecond)
		}
	}

	// starts to write body with good pauses in between
	for {
		if _, err := fmt.Fprintf(w, "booboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboobooboo\n"); err != nil {
			// this allows to quit the go routine when the client disconnects
			break
		}
		z.Flush()
		time.Sleep(250 * time.Millisecond)
	}
}

// simulates server closing immediately the connection without reply
func emptyResponse(w http.ResponseWriter, req *http.Request) {
	hj, _ := w.(http.Hijacker)
	conn, _, _ := hj.Hijack()
	defer func() {
		_ = conn.Close()
	}()
}

// SO MANY REDIRECTS
func infiniteRedirects(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Location", "/infiniteRedirects")
	w.WriteHeader(http.StatusMovedPermanently)
}

// simulates connection dropping in the middle of a valid http response
func unexpectedEOF(w http.ResponseWriter, req *http.Request) {
	hj, _ := w.(http.Hijacker)
	conn, bufrw, _ := hj.Hijack()
	defer func() {
		_ = conn.Close()
	}()
	// reply with bogus data - this should either crash the client or trigger a recoverable error on
	// default retryablehttp requests
	_, _ = bufrw.WriteString("HTTP/1.1 200 OK\n" +
		"Date: Mon, 27 Jul 2009 12:28:53 GMT\n" +
		"Server:\n")
	// "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT" +
	// "Content-Length: -124" +
	// "Content-Type: whatzdacontenttype" +
	// "Connection: drunk")
	_ = bufrw.Flush()
}

// Simulate normal 200 answer with body
func foo(w http.ResponseWriter, req *http.Request) {
	_, _ = fmt.Fprintf(w, "foo")
}

// Server is a configurable instance of the buggy test server. Each instance
// keeps its own state (so tests do not share a global counter) and can bind an
// ephemeral port, avoiding conflicts with other services running locally.
type Server struct {
	httpServer *http.Server
	// count drives the /successAfter endpoint, per instance.
	count atomic.Int64
}

// New returns a new, not yet listening, buggy server.
func New() *Server {
	return &Server{}
}

func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", foo)
	mux.HandleFunc("/successAfter", s.successAfter)
	mux.HandleFunc("/emptyResponse", emptyResponse)
	mux.HandleFunc("/unexpectedEOF", unexpectedEOF)
	mux.HandleFunc("/endlessBody", endlessBody)
	mux.HandleFunc("/endlessWaitTime", endlessWaitTime)
	mux.HandleFunc("/superSlow", superSlow)
	mux.HandleFunc("/messyHeaders", messyHeaders)
	mux.HandleFunc("/messyEncoding", messyEncoding)
	mux.HandleFunc("/infiniteRedirects", infiniteRedirects)
	return mux
}

// Start binds an ephemeral port on 127.0.0.1, serves in the background and
// returns the base URL (e.g. http://127.0.0.1:54321). The listener is bound
// before returning, so the URL is ready to receive requests.
func (s *Server) Start() (string, error) {
	return s.start("127.0.0.1:0")
}

// StartPort binds the given port (all interfaces) and serves in the background.
func (s *Server) StartPort(port int) error {
	_, err := s.start(fmt.Sprintf(":%d", port))
	return err
}

func (s *Server) start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	s.httpServer = &http.Server{Handler: s.mux()}
	go s.httpServer.Serve(ln) //nolint
	return "http://" + ln.Addr().String(), nil
}

// StartTLS binds the given port for TLS and serves in the background.
func (s *Server) StartTLS(port int, certFile, keyFile string) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	s.httpServer = &http.Server{Handler: s.mux()}
	go s.httpServer.ServeTLS(ln, certFile, keyFile) //nolint
	return nil
}

// Close shuts the server down.
func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(context.Background())
	}
	return nil
}

// generates recoverable errors until SuccessAfter attempts => after it 200 + body
func (s *Server) successAfter(w http.ResponseWriter, req *http.Request) {
	successAfter := defaultSuccessAfterThreshold
	if req.FormValue("successAfter") != "" {
		if i, err := strconv.Atoi(req.FormValue("successAfter")); err == nil {
			successAfter = i
		}
	}

	if s.count.Add(1) <= int64(successAfter) {
		hj, _ := w.(http.Hijacker)
		conn, bufrw, _ := hj.Hijack()
		defer func() {
			_ = conn.Close()
		}()
		// reply with bogus data - this should either crash the client or trigger a recoverable error on
		// default retryablehttp requests
		_, _ = bufrw.WriteString("HHHTTP\\1,.1 -500 MAYBEOK\n" +
			"Date: Mon, 27 Jul 2009 12:28:53 GMT\n" +
			"Server: Apache/2.2.14 (Win32)\n" +
			"Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\n" +
			"Content-Length: -124\n" +
			"Content-Type: whatzdacontenttype\n" +
			"Connection: drunk")
		_ = bufrw.Flush()
		return
	}

	// zeroes attempts and return 200 + valid body
	s.count.Store(0)
	_, _ = fmt.Fprintf(w, "foo")
}

var (
	defaultServer    *Server
	defaultServerTLS *Server
)

// Listen on the specified port using a package-level server.
// Deprecated: prefer New().Start() / New().StartPort() for an isolated, port
// configurable instance.
func Listen(port int) {
	defaultServer = New()
	_ = defaultServer.StartPort(port)
}

// ListenTLS because buggyhttp also supports bugged TLS.
// Deprecated: prefer New().StartTLS().
func ListenTLS(port int, certFile, keyFile string) {
	defaultServerTLS = New()
	_ = defaultServerTLS.StartTLS(port, certFile, keyFile)
}

// Stop the package-level servers started via Listen/ListenTLS.
func Stop() {
	if defaultServer != nil {
		_ = defaultServer.Close()
	}
	if defaultServerTLS != nil {
		_ = defaultServerTLS.Close()
	}
}
