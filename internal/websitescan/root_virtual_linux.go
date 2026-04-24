//go:build linux

package websitescan

func rootVirtualDirForPath(webRoot string) ([]VirtualDirInfo, *VirtualDirInfo) {
	if webRoot == "" {
		return []VirtualDirInfo{}, nil
	}
	return linuxRootVirtualDir(webRoot)
}
