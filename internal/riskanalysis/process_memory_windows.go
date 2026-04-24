//go:build windows

package riskanalysis

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CaptureProcessMemory reads readable memory pages from a process up to maxBytes.
func CaptureProcessMemory(pid int, maxBytes int) ([]byte, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("pid must be greater than 0")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultProcessMemoryMaxBytes
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		handle, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
		if err != nil {
			return nil, fmt.Errorf("open process %d: %w", pid, err)
		}
	}
	defer windows.CloseHandle(handle)

	data := make([]byte, 0, initialProcessMemoryCap(maxBytes))
	var address uintptr

	for len(data) < maxBytes {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(handle, address, &mbi, unsafe.Sizeof(mbi)); err != nil {
			if len(data) > 0 {
				break
			}
			return nil, fmt.Errorf("query process memory failed at 0x%x: %w", address, err)
		}
		if mbi.RegionSize == 0 {
			break
		}

		next := mbi.BaseAddress + mbi.RegionSize
		if isReadableMemoryRegion(mbi) {
			remaining := maxBytes - len(data)
			size := regionReadSize(mbi.RegionSize, remaining)
			if size > 0 {
				chunk := make([]byte, size)
				var read uintptr
				err := windows.ReadProcessMemory(handle, mbi.BaseAddress, &chunk[0], uintptr(size), &read)
				if err == nil && read > 0 {
					data = append(data, chunk[:read]...)
				}
			}
		}

		if next <= address {
			break
		}
		address = next
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no readable process memory captured for pid %d", pid)
	}
	return data, nil
}

func initialProcessMemoryCap(maxBytes int) int {
	if maxBytes <= 0 {
		return 0
	}
	const oneMiB = 1024 * 1024
	if maxBytes < oneMiB {
		return maxBytes
	}
	return oneMiB
}

func regionReadSize(region uintptr, remaining int) int {
	if remaining <= 0 || region == 0 {
		return 0
	}
	if region >= uintptr(remaining) {
		return remaining
	}
	return int(region)
}

func isReadableMemoryRegion(mbi windows.MemoryBasicInformation) bool {
	if mbi.State != windows.MEM_COMMIT {
		return false
	}
	if mbi.Protect&(windows.PAGE_GUARD|windows.PAGE_NOACCESS) != 0 {
		return false
	}
	protect := mbi.Protect &^ (windows.PAGE_GUARD | windows.PAGE_NOCACHE | windows.PAGE_WRITECOMBINE)
	switch protect {
	case windows.PAGE_READONLY,
		windows.PAGE_READWRITE,
		windows.PAGE_WRITECOPY,
		windows.PAGE_EXECUTE_READ,
		windows.PAGE_EXECUTE_READWRITE,
		windows.PAGE_EXECUTE_WRITECOPY:
		return true
	default:
		return false
	}
}
