//go:build windows

package filescan

import "context"

// DefaultSignatureVerifier is a placeholder for Authenticode verification.
type DefaultSignatureVerifier struct{}

func (DefaultSignatureVerifier) IsTrusted(ctx context.Context, path string) (bool, error) {
	_ = ctx
	return verifySignature(path)
}
