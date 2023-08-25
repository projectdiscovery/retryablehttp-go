package retryablehttp_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// This test is just to make sure that the default client is initialized
// correctly.
func Test_DefaultHttpClient(t *testing.T) {
	require.NotNil(t, retryablehttp.DefaultHTTPClient)
	resp, err := retryablehttp.DefaultHTTPClient.Get("https://scanme.sh")
	require.Nil(t, err)
	require.NotNil(t, resp)
}

func TestConnectionReuse(t *testing.T) {
	opts := retryablehttp.DefaultOptionsSingle
	client := retryablehttp.NewClient(opts)

	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "this is a test")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	trace := &httptrace.ClientTrace{}
	totalConns := &atomic.Uint32{}
	trace.ConnectStart = func(network, addr string) {
		_ = totalConns.Add(1)
	}

	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := 0; i < 20; i++ {
				req, err := retryablehttp.NewRequest("GET", ts.URL, nil)
				require.Nil(t, err)
				req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
				resp, err := client.Do(req)
				require.Nil(t, err)
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}

	wg.Wait()
	// total number of connections depends on various factors
	// like idle timeout and network condtions etc but in any case
	// it should be less than 10
	require.LessOrEqual(t, totalConns.Load(), uint32(10), "connection reuse failed")
}
