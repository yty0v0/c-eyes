//go:build windows

package benchmark

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	benchmarkMaxPreferredLength = 0xFFFFFFFF
	benchmarkNERRSuccess        = 0
	benchmarkERRORMoreData      = 234
)

var (
	modNetapi32Benchmark   = windows.NewLazySystemDLL("netapi32.dll")
	procNetShareEnum       = modNetapi32Benchmark.NewProc("NetShareEnum")
	procNetApiBufferFreeBk = modNetapi32Benchmark.NewProc("NetApiBufferFree")
)

type windowsShareInfo struct {
	Name            string `json:"name"`
	Type            uint32 `json:"type"`
	Remark          string `json:"remark,omitempty"`
	Path            string `json:"path,omitempty"`
	EveryonePresent bool   `json:"everyone_present"`
}

type benchmarkShareInfo502 struct {
	NetName     *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Passwd      *uint16
	Reserved    uint32
	Security    *windows.SECURITY_DESCRIPTOR
}

func collectWindowsShares() ([]windowsShareInfo, error) {
	worldSID, err := benchmarkWorldSID()
	if err != nil {
		return nil, err
	}

	var (
		resume uint32
		out    []windowsShareInfo
	)

	for {
		var (
			buf     uintptr
			entries uint32
			total   uint32
		)
		r0, _, _ := procNetShareEnum.Call(
			0,
			502,
			uintptr(unsafe.Pointer(&buf)),
			benchmarkMaxPreferredLength,
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)),
		)

		if r0 != benchmarkNERRSuccess && r0 != benchmarkERRORMoreData {
			if buf != 0 {
				_, _, _ = procNetApiBufferFreeBk.Call(buf)
			}
			return nil, windows.Errno(r0)
		}

		if buf != 0 {
			records := unsafe.Slice((*benchmarkShareInfo502)(unsafe.Pointer(buf)), int(entries))
			for _, rec := range records {
				out = append(out, windowsShareInfo{
					Name:            windows.UTF16PtrToString(rec.NetName),
					Type:            rec.Type,
					Remark:          windows.UTF16PtrToString(rec.Remark),
					Path:            windows.UTF16PtrToString(rec.Path),
					EveryonePresent: benchmarkShareHasEveryone(rec.Security, worldSID),
				})
			}
			_, _, _ = procNetApiBufferFreeBk.Call(buf)
		}

		if r0 == benchmarkNERRSuccess {
			break
		}
	}

	return out, nil
}

func benchmarkShareHasEveryone(sd *windows.SECURITY_DESCRIPTOR, worldSID *windows.SID) bool {
	if sd == nil || worldSID == nil {
		return false
	}

	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if windows.EqualSid(sid, worldSID) {
			return true
		}
	}
	return false
}

func benchmarkWorldSID() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinWorldSid)
}

func listWindowsFixedDrives() ([]windowsDriveRecord, error) {
	size, err := windows.GetLogicalDriveStrings(0, nil)
	if err != nil {
		return nil, err
	}
	buf := make([]uint16, size+1)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil {
		return nil, err
	}

	records := make([]windowsDriveRecord, 0, 8)
	start := 0
	for i := 0; i < int(n); i++ {
		if buf[i] != 0 {
			continue
		}
		if i == start {
			start = i + 1
			continue
		}
		drive := windows.UTF16ToString(buf[start:i])
		start = i + 1
		if strings.TrimSpace(drive) == "" {
			continue
		}
		ptr, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		if windows.GetDriveType(ptr) != windows.DRIVE_FIXED {
			continue
		}
		fsBuf := make([]uint16, 64)
		if err := windows.GetVolumeInformation(ptr, nil, 0, nil, nil, nil, &fsBuf[0], uint32(len(fsBuf))); err != nil {
			records = append(records, windowsDriveRecord{
				Name:       drive,
				FileSystem: fmt.Sprintf("error: %v", err),
				DriveType:  windows.DRIVE_FIXED,
			})
			continue
		}
		records = append(records, windowsDriveRecord{
			Name:       drive,
			FileSystem: strings.TrimSpace(windows.UTF16ToString(fsBuf)),
			DriveType:  windows.DRIVE_FIXED,
		})
	}
	return records, nil
}
