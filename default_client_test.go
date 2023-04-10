package retryablehttp_test

import (
	"testing"

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
