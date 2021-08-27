package retryablehttp

import (
	"crypto/tls"
	"net/http"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"golang.org/x/net/http2"
)

// Client is used to make HTTP requests. It adds additional functionality
// like automatic retries to tolerate minor outages.
type Client struct {
	// HTTPClient is the internal HTTP client (http1x + http2 via connection upgrade upgrade).
	HTTPClient *http.Client
	// HTTPClient2 is the internal HTTP2 client configured to fallback to native http2 at transport level
	HTTPClient2 *http.Client
	// HTTPClient3 contains expertimental support for HTTP3 QUIC protocol - According to RFC7838 if the protocol is supported the response will contain the following header with the alternate service ip:port:
	// Alt-Svc: h3="ip:port"
	HTTPClient3 *http.Client

	requestCounter uint32

	// RequestLogHook allows a user-supplied function to be called
	// before each retry.
	RequestLogHook RequestLogHook
	// ResponseLogHook allows a user-supplied function to be called
	// with the response from each HTTP request executed.
	ResponseLogHook ResponseLogHook
	// ErrorHandler specifies the custom error handler to use, if any
	ErrorHandler ErrorHandler

	// CheckRetry specifies the policy for handling retries, and is called
	// after each request. The default policy is DefaultRetryPolicy.
	CheckRetry CheckRetry
	// Backoff specifies the policy for how long to wait between retries
	Backoff Backoff

	options Options
}

// Options contains configuration options for the client
type Options struct {
	// RetryWaitMin is the minimum time to wait for retry
	RetryWaitMin time.Duration
	// RetryWaitMax is the maximum time to wait for retry
	RetryWaitMax time.Duration
	// Timeout is the maximum time to wait for the request
	Timeout time.Duration
	// RetryMax is the maximum number of retries
	RetryMax int
	// RespReadLimit is the maximum HTTP response size to read for
	// connection being reused.
	RespReadLimit int64
	// Verbose specifies if debug messages should be printed
	Verbose bool
	// KillIdleConn specifies if all keep-alive connections gets killed
	KillIdleConn bool
	// should retry on http2 if alt-svc header provided?
	HTTP2 bool
	// should retry on http3 if alt-svc header provided?
	HTTP3 bool
}

// DefaultOptionsSpraying contains the default options for host spraying
// scenarios where lots of requests need to be sent to different hosts.
var DefaultOptionsSpraying = Options{
	RetryWaitMin:  1 * time.Second,
	RetryWaitMax:  30 * time.Second,
	Timeout:       30 * time.Second,
	RetryMax:      5,
	RespReadLimit: 4096,
	KillIdleConn:  true,
	HTTP2:         false,
	HTTP3:         false,
}

// DefaultOptionsSingle contains the default options for host bruteforce
// scenarios where lots of requests need to be sent to a single host.
var DefaultOptionsSingle = Options{
	RetryWaitMin:  1 * time.Second,
	RetryWaitMax:  30 * time.Second,
	Timeout:       30 * time.Second,
	RetryMax:      5,
	RespReadLimit: 4096,
	KillIdleConn:  false,
	HTTP2:         false,
	HTTP3:         false,
}

// NewClient creates a new Client with default settings.
func NewClient(options Options) *Client {
	httpclient := DefaultClient()
	httpclient2 := DefaultClient()
	if err := http2.ConfigureTransport(httpclient2.Transport.(*http.Transport)); err != nil {
		return nil
	}
	http3client := DefaultClient()
	h3Transport := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		QuicConfig: &quic.Config{},
	}
	http3client.Transport = h3Transport

	// if necessary adjusts per-request timeout proportionally to general timeout (30%)
	if options.Timeout > time.Second*15 {
		httpclient.Timeout = time.Duration(options.Timeout.Seconds()*0.3) * time.Second
	}

	c := &Client{
		HTTPClient:  httpclient,
		HTTPClient2: httpclient2,
		HTTPClient3: http3client,
		CheckRetry:  DefaultRetryPolicy(),
		Backoff:     DefaultBackoff(),
		options:     options,
	}

	c.setKillIdleConnections()
	return c
}

// NewWithHTTPClient creates a new Client with default settings and provided http.Client
func NewWithHTTPClient(client *http.Client, options Options) *Client {
	httpclient2 := DefaultClient()
	httpclient2.Transport = client.Transport.(*http.Transport).Clone()
	if err := http2.ConfigureTransport(httpclient2.Transport.(*http.Transport)); err != nil {
		return nil
	}
	http3client := DefaultClient()
	h3Transport := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		QuicConfig: &quic.Config{},
	}
	http3client.Transport = h3Transport
	c := &Client{
		HTTPClient:  client,
		HTTPClient2: httpclient2,
		HTTPClient3: http3client,
		CheckRetry:  DefaultRetryPolicy(),
		Backoff:     DefaultBackoff(),

		options: options,
	}

	c.setKillIdleConnections()
	return c
}

// setKillIdleConnections sets the kill idle conns switch in two scenarios
//  1. If the http.Client has settings that require us to do so.
//  2. The user has enabled it by default, in which case we have nothing to do.
func (c *Client) setKillIdleConnections() {
	if c.HTTPClient != nil || !c.options.KillIdleConn {
		if b, ok := c.HTTPClient.Transport.(*http.Transport); ok {
			c.options.KillIdleConn = b.DisableKeepAlives || b.MaxConnsPerHost < 0
		}
	}
}
