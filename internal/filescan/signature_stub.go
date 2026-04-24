//go:build !windows

package filescan

import "context"

// DefaultSignatureVerifier is a no-op verifier on non-Windows platforms.
type DefaultSignatureVerifier struct{}

func (DefaultSignatureVerifier) IsTrusted(ctx context.Context, path string) (bool, error) {
	_ = ctx
	_ = path
	return false, nil
}
