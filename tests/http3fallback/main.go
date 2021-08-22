// from https://github.com/lucas-clemente/quic-go/blob/master/example/main.go
package main

import (
	"io"
	"log"
	"net/http"

	_ "net/http/pprof"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/projectdiscovery/retryablehttp-go"
)

func main() {
	// h1 server
	go func() {
		h1server := http.Server{Handler: h1handler(), Addr: "localhost:6060"}
		log.Println("HTTP1 listening on TCP localhost:6060")
		log.Println(h1server.ListenAndServeTLS("cert.pem", "priv.key"))
	}()
	// h3 server
	go func() {
		h3server := http3.Server{Server: &http.Server{Handler: h3handler(), Addr: "localhost:6060"}, QuicConfig: &quic.Config{}}
		log.Println("HTTP3 listening on UDP localhost:6060")
		log.Println(h3server.ListenAndServeTLS("cert.pem", "priv.key"))
	}()
	// client with fallback
	options := retryablehttp.DefaultOptionsSpraying
	options.HTTP3 = true
	rhclient := retryablehttp.NewClient(options)
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://localhost:6060/", nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := rhclient.Do(req)
	log.Fatal(resp, err)
}

func h1handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("http1 request from", r.RemoteAddr)
		w.Header().Add("Alt-Svc", "h3=\"localhost:6060\"")
		w.WriteHeader(500)
		io.WriteString(w, "<html><body>hello from h1</body></html>")
	})

	return mux
}

func h3handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/demo", func(w http.ResponseWriter, r *http.Request) {
		log.Println("http3 request from", r.RemoteAddr)
		io.WriteString(w, "<html><body>hello from h3</body></html>")
	})

	return mux
}
