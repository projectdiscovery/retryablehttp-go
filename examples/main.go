package main

import (
	"fmt"
	"io"

	"github.com/projectdiscovery/retryablehttp-go"
)

func main() {
	opts := retryablehttp.DefaultOptionsSpraying
	// opts := retryablehttp.DefaultOptionsSingle // use single options for single host
	client := retryablehttp.NewClient(opts)
	resp, err := client.Get("https://scanme.sh")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Data: %v\n", string(data))
}
