//go:build windows

package filescan

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	versionDLL                 = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSize = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = versionDLL.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = versionDLL.NewProc("VerQueryValueW")
)

func peVersionInfo(path string) *FileVersionInfo {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}

	var handle uint32
	size, _, _ := procGetFileVersionInfoSize.Call(uintptr(unsafe.Pointer(path16)), uintptr(unsafe.Pointer(&handle)))
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	ok, _, _ := procGetFileVersionInfo.Call(uintptr(unsafe.Pointer(path16)), 0, uintptr(size), uintptr(unsafe.Pointer(&buf[0])))
	if ok == 0 {
		return nil
	}

	lang, codepage := queryTranslation(buf)
	original := queryVersionString(buf, lang, codepage, "OriginalFilename")
	description := queryVersionString(buf, lang, codepage, "FileDescription")
	if original == "" && description == "" {
		return nil
	}

	info := &FileVersionInfo{}
	if original != "" {
		info.OriginalFilename = &original
	}
	if description != "" {
		info.FileDescription = &description
	}
	return info
}

func queryTranslation(buf []byte) (uint16, uint16) {
	ptr, length, ok := verQueryValue(buf, `\VarFileInfo\Translation`)
	if ok && ptr != nil && length >= 4 {
		raw := unsafe.Slice((*byte)(ptr), int(length))
		if len(raw) >= 4 {
			lang := binary.LittleEndian.Uint16(raw[0:2])
			codepage := binary.LittleEndian.Uint16(raw[2:4])
			if lang != 0 && codepage != 0 {
				return lang, codepage
			}
		}
	}
	return 0x0409, 0x04B0
}

func queryVersionString(buf []byte, lang uint16, codepage uint16, key string) string {
	sub := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, lang, codepage, key)
	ptr, _, ok := verQueryValue(buf, sub)
	if !ok || ptr == nil {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(ptr))
}

func verQueryValue(buf []byte, subBlock string) (unsafe.Pointer, uint32, bool) {
	if len(buf) == 0 {
		return nil, 0, false
	}
	subPtr, err := windows.UTF16PtrFromString(subBlock)
	if err != nil {
		return nil, 0, false
	}
	var outPtr unsafe.Pointer
	var outLen uint32
	r1, _, _ := procVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(subPtr)),
		uintptr(unsafe.Pointer(&outPtr)),
		uintptr(unsafe.Pointer(&outLen)),
	)
	if r1 == 0 {
		return nil, 0, false
	}
	return outPtr, outLen, true
}
