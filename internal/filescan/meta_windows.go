//go:build windows

package filescan

import (
	"os"
	"syscall"
	"time"
)

func fillFileMetaPlatform(path string, info os.FileInfo, meta *FileMeta) {
	_ = path
	sys, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || sys == nil {
		return
	}

	ctime := time.Unix(0, sys.CreationTime.Nanoseconds()).UTC()
	atime := time.Unix(0, sys.LastAccessTime.Nanoseconds()).UTC()
	mtime := time.Unix(0, sys.LastWriteTime.Nanoseconds()).UTC()

	meta.CreationTime = &ctime
	meta.AccessTime = &atime
	meta.ModifiedTime = mtime

	var attrs []string
	if sys.FileAttributes&syscall.FILE_ATTRIBUTE_HIDDEN != 0 {
		attrs = append(attrs, "HIDDEN")
	}
	if sys.FileAttributes&syscall.FILE_ATTRIBUTE_SYSTEM != 0 {
		attrs = append(attrs, "SYSTEM")
	}
	if sys.FileAttributes&syscall.FILE_ATTRIBUTE_READONLY != 0 {
		attrs = append(attrs, "READONLY")
	}
	if len(attrs) > 0 {
		meta.Attributes = attrs
	}
}
