package retryablehttp

import (
	"os"
	"sync"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/stretchr/testify/require"
)

// TestGetFastDialerKeepsDNSCacheInMemory verifies that the shared dialer keeps
// its DNS cache in memory even when fastdialer defaults to a disk cache.
func TestGetFastDialerKeepsDNSCacheInMemory(t *testing.T) {
	// A disk cache keeps its database in a new directory under the temporary
	// directory.
	tmpDir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, tmpDir)
	}

	defaults := fastdialer.DefaultOptions
	t.Cleanup(func() { fastdialer.DefaultOptions = defaults })
	fastdialer.DefaultOptions.CacheType = fastdialer.Disk

	// Build a new shared dialer, and restore the one from package init
	// afterwards.
	prevInit, prevDialer, prevErr := fdInit, fd, err
	t.Cleanup(func() { fdInit, fd, err = prevInit, prevDialer, prevErr })
	fdInit = &sync.Once{}

	dialer, dialerErr := getFastDialer()
	require.NoError(t, dialerErr)
	t.Cleanup(dialer.Close)

	entries, readErr := os.ReadDir(tmpDir)
	require.NoError(t, readErr)
	require.Empty(t, entries, "shared dialer created an on-disk DNS cache")
}
