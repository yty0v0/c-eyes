//go:build windows

package filescan

import "golang.org/x/sys/windows"

func listRoots() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var roots []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		drive := string(rune('A'+i)) + ":\\"
		roots = append(roots, drive)
	}
	return roots
}
