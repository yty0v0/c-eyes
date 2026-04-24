//go:build !windows

package filescan

func peVersionInfo(path string) *FileVersionInfo {
	_ = path
	return nil
}
