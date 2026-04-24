//go:build !windows

package filescan

func fileContextInfo(path string) *FileContextInfo {
	_ = path
	return nil
}
