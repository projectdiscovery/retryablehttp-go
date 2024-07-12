package retryablehttp

import (
	"bufio"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// MiddlewareOnBeforeRequestAddHeaders is a middleware that adds headers to the request
// before it is sent.
func MiddlewareOnBeforeRequestAddHeaders(headers map[string]string) ClientRequestMiddleware {
	return func(client *Client, req *Request) error {
		for k, v := range headers {
			if values, ok := req.Request.Header[k]; ok && len(values) > 0 {
				continue
			}
			req.Request.Header.Add(k, v)
		}
		return nil
	}
}

var (
	imperasonateChromeHeaders = map[string]string{
		"pragma":                    "no-cache",
		"cache-control":             "no-cache",
		"sec-ch-ua":                 `"Not/A)Brand";v="99", "Chromium";v="109", "Google Chrome";v="109"`,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"macOS"`,
		"upgrade-insecure-requests": "1",
		"user-agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"sec-fetch-site":            "none",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-user":            "?1",
		"sec-fetch-dest":            "document",
		"accept-language":           "en-GB,en-US;q=0.9,en;q=0.8",
		"accept-encoding":           "gzip, deflate, br, zstd",
	}
)

// bypassJA3Transport is a transport that supports bypassing JA3 fingeprint
// and also decides whether to use http1 or http2 based on the server response.
//
// The idea is to pass default configs and use this roundtripper
type bypassJA3Transport struct {
	tr1         *http.Transport
	tr2         *http2.Transport
	clientHello utls.ClientHelloID
}

func (b *bypassJA3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "https":
		return b.httpsRoundTrip(req)
	case "http":
		return b.tr1.RoundTrip(req)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", req.URL.Scheme)
	}
}

func (b *bypassJA3Transport) httpsRoundTrip(req *http.Request) (*http.Response, error) {
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}

	fd, _ := getFastDialer()
	tlsConn, err := fd.DialTLSWithConfigImpersonate(req.Context(), "tcp", fmt.Sprintf("%s:%s", req.URL.Host, port), b.tr1.TLSClientConfig, impersonate.Chrome, nil)
	if err != nil {
		return nil, fmt.Errorf("tcp net dial fail: %w", err)
	}
	utlsConnection, ok := tlsConn.(*utls.UConn)
	if !ok {
		return nil, fmt.Errorf("tcp net dial fail: %w", err)
	}

	httpVersion := utlsConnection.ConnectionState().NegotiatedProtocol
	switch httpVersion {
	case "h2":
		conn, err := b.tr2.NewClientConn(tlsConn)
		if err != nil {
			return nil, fmt.Errorf("create http2 client with connection fail: %w", err)
		}
		return conn.RoundTrip(req)
	case "http/1.1", "":
		err := req.Write(tlsConn)
		if err != nil {
			return nil, fmt.Errorf("write http1 tls connection fail: %w", err)
		}
		return http.ReadResponse(bufio.NewReader(tlsConn), req)
	default:
		return nil, fmt.Errorf("unsuported http version: %s", httpVersion)
	}
}
