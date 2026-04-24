//go:build !windows

package filescan

import (
	"errors"
	"time"
)

// UnsupportedIdleDetector returns an error on non-Windows platforms.
type UnsupportedIdleDetector struct{}

func (UnsupportedIdleDetector) IdleFor() (time.Duration, error) {
	return 0, errors.New("idle detection unsupported")
}
