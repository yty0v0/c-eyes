//go:build !windows

package filescan

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func fillFileMetaPlatform(path string, info os.FileInfo, meta *FileMeta) {
	_ = path
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || stat == nil {
		return
	}

	atime := time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec)).UTC()
	meta.AccessTime = &atime

	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	gid := strconv.FormatUint(uint64(stat.Gid), 10)
	owner := uid
	group := gid

	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		owner = u.Username
	}
	if g, err := user.LookupGroupId(gid); err == nil && g.Name != "" {
		group = g.Name
	}

	meta.Owner = &owner
	meta.Group = &group

	mode := info.Mode().Perm()
	if info.Mode()&os.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if info.Mode()&os.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if info.Mode()&os.ModeSticky != 0 {
		mode |= 0o1000
	}
	modeStr := fmt.Sprintf("%#o", mode)
	meta.Mode = &modeStr
}
