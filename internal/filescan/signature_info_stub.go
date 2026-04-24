//go:build !windows

package filescan

func signatureInfo(path string) *FileSignatureInfo {
	_ = path
	return nil
}
