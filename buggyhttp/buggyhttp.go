// Package buggyhttp is a webserver affected by any kind of network issues
package buggyhttp

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
		fmt.Fprint(w, oneencodingfrommany)
	}
}

// SO MANY DELAYS
func superSlow(w http.ResponseWriter, req *http.Request) {
	// echoes out all requests headers (just because we are lazy)
	z := w.(http.Flusher)
	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
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
	defer conn.Close()
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
	defer conn.Close()
	// reply with bogus data - this should either crash the client or trigger a recoverable error on
	// default retryablehttp requests
	_, _ = bufrw.WriteString("HTTP/1.1 200 OK\n" +
		"Date: Mon, 27 Jul 2009 12:28:53 GMT\n" +
		"Server:\n")
	// "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT" +
	// "Content-Length: -124" +
	// "Content-Type: whatzdacontenttype" +
	// "Connection: drunk")
	bufrw.Flush()
}

// Simulate normal 200 answer with body
func foo(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "foo")
}

// generates recoverable errors until SuccessAfter attempts => after it 200 + body
var count int // as of now a local horrible variable suffice
func successAfter(w http.ResponseWriter, req *http.Request) {
	var successAfter int = defaultSuccessAfterThreshold
	if req.FormValue("successAfter") != "" {
		if i, err := strconv.Atoi(req.FormValue("successAfter")); err == nil {
			successAfter = i
		}
	}

	count++
	if count <= successAfter {
		hj, _ := w.(http.Hijacker)
		conn, bufrw, _ := hj.Hijack()
		defer conn.Close()
		// reply with bogus data - this should either crash the client or trigger a recoverable error on
		// default retryablehttp requests
		_, _ = bufrw.WriteString("HHHTTP\\1,.1 -500 MAYBEOK\n" +
			"Date: Mon, 27 Jul 2009 12:28:53 GMT\n" +
			"Server: Apache/2.2.14 (Win32)\n" +
			"Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\n" +
			"Content-Length: -124\n" +
			"Content-Type: whatzdacontenttype\n" +
			"Connection: drunk")
		bufrw.Flush()
		return
	}

	// zeroes attempts and return 200 + valid body
	count = 0
	fmt.Fprintf(w, "foo")
}



var (
	server    *http.Server
	serverTLS *http.Server
)

// Listen on specified port
func Listen(port int) {

	mux := http.NewServeMux()
	mux.HandleFunc("/foo", foo)
	mux.HandleFunc("/successAfter", successAfter)
	mux.HandleFunc("/emptyResponse", emptyResponse)
	mux.HandleFunc("/unexpectedEOF", unexpectedEOF)
	mux.HandleFunc("/endlessBody", endlessBody)
	mux.HandleFunc("/endlessWaitTime", endlessWaitTime)
	mux.HandleFunc("/superSlow", superSlow)
	mux.HandleFunc("/messyHeaders", messyHeaders)
	mux.HandleFunc("/messyEncoding", messyEncoding)
	mux.HandleFunc("/infiniteRedirects", infiniteRedirects)

	server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go server.ListenAndServe() //nolint
}

// ListenTLS because buggyhttp also supports bugged TLS
func ListenTLS(port int, certFile, keyFile string) {
	serverTLS = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: newMux(),
	}

	go serverTLS.ListenAndServeTLS(certFile, keyFile) //nolint
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", foo)
	mux.HandleFunc("/successAfter", successAfter)
	mux.HandleFunc("/emptyResponse", emptyResponse)
	mux.HandleFunc("/unexpectedEOF", unexpectedEOF)
	mux.HandleFunc("/endlessBody", endlessBody)
	mux.HandleFunc("/endlessWaitTime", endlessWaitTime)
	mux.HandleFunc("/superSlow", superSlow)
	mux.HandleFunc("/messyHeaders", messyHeaders)
	mux.HandleFunc("/infiniteRedirects", infiniteRedirects)
	return mux
}

// Stop the server
func Stop() {
	if server != nil {
		_ = server.Shutdown(context.Background())
	}
	if serverTLS != nil {
		_ = serverTLS.Shutdown(context.Background())
	}
}
