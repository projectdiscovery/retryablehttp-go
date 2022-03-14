package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/projectdiscovery/retryablehttp-go/buggyhttp"
)

func WaitForCtrlC() {
	var endwaiter sync.WaitGroup
	endwaiter.Add(1)
	signalchannel := make(chan os.Signal, 1)
	signal.Notify(signalchannel, os.Interrupt)
	go func() {
		<-signalchannel
		endwaiter.Done()
	}()
	endwaiter.Wait()
}

func main() {
	buggyhttp.Listen(8080)
	buggyhttp.ListenTLS(8081, "server.crt", "server.key")
	fmt.Printf("Press Ctrl+C to end\n")
	WaitForCtrlC()
	fmt.Printf("\n")
}
