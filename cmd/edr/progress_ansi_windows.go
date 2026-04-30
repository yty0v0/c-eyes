//go:build windows

package main

import "golang.org/x/sys/windows"

const enableVirtualTerminalProcessing = 0x0004

func enableProgressANSIMode(fd uintptr) bool {
	handle := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|enableVirtualTerminalProcessing) == nil
}

func terminalWidth(fd uintptr) (int, bool) {
	handle := windows.Handle(fd)
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(handle, &info); err != nil {
		return 0, false
	}
	width := int(info.Window.Right-info.Window.Left) + 1
	if width <= 0 {
		return 0, false
	}
	return width, true
}
