//go:build !windows

package filescan

import (
	"context"
	"errors"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func collectRecentPlatform(ctx context.Context, params FileScanParams, since time.Time) ([]ScanTask, bool, error) {
	dirs := highRiskDirs()
	if len(dirs) == 0 {
		return nil, false, nil
	}
	tasks, err := collectRecentInotify(ctx, dirs, normalizeSmartMaxTargets(params.MaxTargets))
	if err != nil || len(tasks) == 0 {
		return nil, false, nil
	}
	return tasks, true, nil
}

func collectRecentInotify(ctx context.Context, dirs []string, limit int) ([]ScanTask, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	watchMap := make(map[int]string)
	mask := uint32(unix.IN_CREATE | unix.IN_MODIFY | unix.IN_MOVED_TO | unix.IN_ATTRIB)
	for _, dir := range dirs {
		wd, err := unix.InotifyAddWatch(fd, dir, mask)
		if err != nil {
			continue
		}
		watchMap[wd] = dir
	}
	if len(watchMap) == 0 {
		return nil, errors.New("no inotify watches")
	}

	buf := make([]byte, 4096)
	tasks := make([]ScanTask, 0, limit)
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && len(tasks) < limit {
		select {
		case <-ctx.Done():
			return tasks, ctx.Err()
		default:
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			break
		}
		offset := 0
		for offset < n {
			event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]
			name := string(nameBytes)
			base := watchMap[int(event.Wd)]
			if base != "" && name != "" {
				path := filepath.Join(base, name)
				if isInterestingExtension(path) {
					tasks = append(tasks, ScanTask{
						Path:   path,
						Source: SourceRecent,
						Mode:   ScanModeSmart,
					})
					if len(tasks) >= limit {
						break
					}
				}
			}
			offset += unix.SizeofInotifyEvent + int(event.Len)
		}
	}
	return dedupeTasks(tasks), nil
}
