//go:build !windows

package main

import "golang.org/x/sys/unix"

func enableProgressANSIMode(fd uintptr) bool {
	_ = fd
	return true
}

func terminalWidth(fd uintptr) (int, bool) {
	ws, err := unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ)
	if err != nil || ws == nil || ws.Col == 0 {
		return 0, false
	}
	return int(ws.Col), true
}
