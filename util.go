package retryablehttp

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/projectdiscovery/stringsutil"
)

// Discard is an helper function that discards the response body and closes the underlying connection
func Discard(req *Request, resp *http.Response, RespReadLimit int64) {
	_, err := io.Copy(ioutil.Discard, io.LimitReader(resp.Body, RespReadLimit))
	if err != nil {
		req.Metrics.DrainErrors++
	}
	resp.Body.Close()
}

func HasHTTP2(resp *http.Response) (bool, string, error) {
	return HasHTTPX(resp, "h2")
}

func HasHTTP3(resp *http.Response) (bool, string, error) {
	return HasHTTPX(resp, "h3")
}

func HasHTTPX(resp *http.Response, protocol string) (bool, string, error) {
	if resp == nil {
		return false, "", errors.New("response is nil")
	}

	if altsvcHeader := resp.Header.Get("Alt-Svc"); stringsutil.HasPrefixI(altsvcHeader, protocol+"=") {
		ipPort := stringsutil.Before(stringsutil.After(altsvcHeader, protocol+"=\""), "\"")
		return true, ipPort, nil
	}

	return false, "", nil
}
