//go:build !windows

package filescan

func listRoots() []string {
	return []string{"/"}
}
