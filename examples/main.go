package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	url   string
	short bool
)

func main() {
	flag.StringVar(&url, "url", "https://scanme.sh", "URL to fetch")
	flag.BoolVar(&short, "short", false, "Skip printing http response body")
	flag.Parse()

	// close connection after each request
	opts := retryablehttp.DefaultOptionsSpraying
	// opts := retryablehttp.DefaultOptionsSingle // use single options for single host
	client := retryablehttp.NewClient(opts)
	resp, err := client.Get(url)
	if err != nil {
		panic(err)
	}

	bin, err := httputil.DumpResponse(resp, !short)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(bin))

	// connection reuse
	opts = retryablehttp.DefaultOptionsSingle
	client = retryablehttp.NewClient(opts)

	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "this is a test")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := 0; i < 20; i++ {
				resp, err := client.Get(ts.URL)
				if err != nil {
					log.Println(err)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}

	wg.Wait()
}
