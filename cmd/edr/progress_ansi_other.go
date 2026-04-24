//go:build !windows

package main

func enableProgressANSIMode(fd uintptr) bool {
	_ = fd
	return true
}
