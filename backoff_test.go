package retryablehttp

import (
	"testing"
	"time"
)

func TestFullJitterBackoffFirstRetryNoPanic(t *testing.T) {
	backoff := FullJitterBackoff()
	min := 100 * time.Millisecond
	max := 5 * time.Second

	for _, attemptNum := range []int{0, 1, 2, 5, 10} {
		wait := backoff(min, max, attemptNum, nil)
		if wait < 0 {
			t.Fatalf("attemptNum=%d: negative backoff duration %v", attemptNum, wait)
		}
		if wait > max {
			t.Fatalf("attemptNum=%d: backoff %v exceeds max %v", attemptNum, wait, max)
		}
	}
}
