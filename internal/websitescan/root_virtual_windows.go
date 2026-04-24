//go:build windows

package websitescan

func rootVirtualDirForPath(webRoot string) ([]VirtualDirInfo, *VirtualDirInfo) {
	if webRoot == "" {
		return []VirtualDirInfo{}, nil
	}
	return windowsRootVirtualDir(webRoot)
}
