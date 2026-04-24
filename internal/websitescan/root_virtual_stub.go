//go:build !windows && !linux

package websitescan

func rootVirtualDirForPath(webRoot string) ([]VirtualDirInfo, *VirtualDirInfo) {
	if webRoot == "" {
		return []VirtualDirInfo{}, nil
	}
	rootPath := nullableString(webRoot)
	item := VirtualDirInfo{
		Path:         strPtr("/"),
		PhysicalPath: rootPath,
		Root:         boolPtr(true),
		ACLs:         []ACLInfo{},
	}
	return []VirtualDirInfo{item}, &item
}
