package retryablehttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Source: https://github.com/imroc/req/blob/master/client_impersonate.go

// Client is used to make HTTP requests. It adds additional functionality
// like automatic retries to tolerate minor outages.
type Client struct {
	// OnBeforeRequest is a list of functions that can be used to modify a request
	OnBeforeRequest []ClientRequestMiddleware

	// HTTPClient is the internal HTTP client (http1x + http2 via connection upgrade upgrade).
	HTTPClient *http.Client
	// HTTPClient is the internal HTTP client configured to fallback to native http2 at transport level
	HTTPClient2 *http.Client

	requestCounter atomic.Uint32

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

// ClientRequestMiddleware is a function that can be used to modify a request
// before it is sent by the client.
type ClientRequestMiddleware func(client *Client, req *Request) error

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
	// Custom CheckRetry policy
	CheckRetry CheckRetry
	// Custom Backoff policy
	Backoff Backoff
	// NoAdjustTimeout disables automatic adjustment of HTTP request timeout
	NoAdjustTimeout bool
	// Custom http client
	HttpClient *http.Client

	// ImpersonateChrome specifies if the client should impersonate Chrome
	ImpersonateChrome bool
}

// DefaultOptionsSpraying contains the default options for host spraying
// scenarios where lots of requests need to be sent to different hosts.
var DefaultOptionsSpraying = Options{
	RetryWaitMin:    1 * time.Second,
	RetryWaitMax:    30 * time.Second,
	Timeout:         30 * time.Second,
	RetryMax:        5,
	RespReadLimit:   4096,
	KillIdleConn:    true,
	NoAdjustTimeout: true,
}

// DefaultOptionsSingle contains the default options for host bruteforce
// scenarios where lots of requests need to be sent to a single host.
var DefaultOptionsSingle = Options{
	RetryWaitMin:    1 * time.Second,
	RetryWaitMax:    30 * time.Second,
	Timeout:         30 * time.Second,
	RetryMax:        5,
	RespReadLimit:   4096,
	KillIdleConn:    false,
	NoAdjustTimeout: true,
}

// NewClient creates a new Client with default settings.
func NewClient(options Options) *Client {
	var httpclient *http.Client
	var httptransport *http.Transport
	if options.HttpClient != nil {
		httpclient = options.HttpClient
	} else if options.KillIdleConn {
		httpclient = DefaultClient()
	} else {
		httpclient = DefaultPooledClient()
	}
	httptransport = httpclient.Transport.(*http.Transport)

	httpclient2 := DefaultClient()
	// This transport is only used during impersonation so we
	// set according to chrome options.
	httptransport2 := &http2.Transport{
		IdleConnTimeout: 90 * time.Second,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient, // Renegotiation is not supported in TLS 1.3 as per docs
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		MaxHeaderListSize:         262144,
		MaxDecoderHeaderTableSize: 65536,
		MaxEncoderHeaderTableSize: 65536,
	}
	if err := http2.ConfigureTransport(httpclient2.Transport.(*http.Transport)); err != nil {
		return nil
	}

	var retryPolicy CheckRetry
	var backoff Backoff

	retryPolicy = DefaultRetryPolicy()
	if options.CheckRetry != nil {
		retryPolicy = options.CheckRetry
	}

	backoff = DefaultBackoff()
	if options.Backoff != nil {
		backoff = options.Backoff
	}

	// add timeout to clients
	if options.Timeout > 0 {
		httpclient.Timeout = options.Timeout
		httpclient2.Timeout = options.Timeout
	}

	// if necessary adjusts per-request timeout proportionally to general timeout (30%)
	if options.Timeout > time.Second*15 && options.RetryMax > 1 && !options.NoAdjustTimeout {
		httpclient.Timeout = time.Duration(options.Timeout.Seconds()*0.3) * time.Second
	}

	c := &Client{
		HTTPClient:  httpclient,
		HTTPClient2: httpclient2,
		CheckRetry:  retryPolicy,
		Backoff:     backoff,
		options:     options,
	}
	if options.ImpersonateChrome {
		c.OnBeforeRequest = append(c.OnBeforeRequest, MiddlewareOnBeforeRequestAddHeaders(imperasonateChromeHeaders))
		httptransport2.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			fd, _ := getFastDialer()
			return fd.DialTLSWithConfigImpersonate(ctx, network, addr, cfg, impersonate.Chrome, nil)
		}
		c.HTTPClient.Transport = &bypassJA3Transport{
			tr1:         httptransport,
			tr2:         httptransport2,
			clientHello: utls.HelloChrome_106_Shuffle,
		}
	}

	c.setKillIdleConnections()
	return c
}

// NewWithHTTPClient creates a new Client with custom http client
// Deprecated: Use options.HttpClient
func NewWithHTTPClient(client *http.Client, options Options) *Client {
	options.HttpClient = client
	return NewClient(options)
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
