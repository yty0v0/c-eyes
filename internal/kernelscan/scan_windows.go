//go:build windows

package kernelscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	psapiDLL                     = windows.NewLazySystemDLL("psapi.dll")
	procEnumDeviceDrivers        = psapiDLL.NewProc("EnumDeviceDrivers")
	procGetDeviceDriverBaseNameW = psapiDLL.NewProc("GetDeviceDriverBaseNameW")
	procGetDeviceDriverFileNameW = psapiDLL.NewProc("GetDeviceDriverFileNameW")
)

type windowsKernelScanProvider struct{}

func defaultKernelScanProvider() KernelScanProvider {
	return windowsKernelScanProvider{}
}

func (windowsKernelScanProvider) Collect(ctx context.Context) ([]KernelModuleInfo, error) {
	return collectWindowsKernelModules(ctx)
}

func collectWindowsKernelModules(ctx context.Context) ([]KernelModuleInfo, error) {
	bases, err := enumWindowsDriverBases()
	if err != nil {
		return nil, err
	}

	rows := make([]KernelModuleInfo, 0, len(bases))
	for _, base := range bases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		name := getWindowsDriverBaseName(base)
		path := normalizeWindowsDriverPath(getWindowsDriverPath(base))
		version, desc := fileVersionInfo(path)
		size := windowsFileSize(path)

		row := KernelModuleInfo{
			ModuleName:  nullableString(name),
			Description: desc,
			Path:        nullableString(path),
			Version:     version,
			Size:        nullableString(size),
			Depends:     []string{},
			Holders:     []string{},
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		li := ""
		if rows[i].ModuleName != nil {
			li = strings.ToLower(*rows[i].ModuleName)
		}
		lj := ""
		if rows[j].ModuleName != nil {
			lj = strings.ToLower(*rows[j].ModuleName)
		}
		return li < lj
	})
	return rows, nil
}

func enumWindowsDriverBases() ([]uintptr, error) {
	size := int(unsafe.Sizeof(uintptr(0)))
	capacity := 1024

	for {
		bases := make([]uintptr, capacity)
		if len(bases) == 0 {
			return nil, nil
		}
		bufferBytes := uint32(len(bases) * size)
		var needed uint32

		ret, _, callErr := procEnumDeviceDrivers.Call(
			uintptr(unsafe.Pointer(&bases[0])),
			uintptr(bufferBytes),
			uintptr(unsafe.Pointer(&needed)),
		)
		if ret == 0 {
			if callErr != windows.ERROR_SUCCESS && callErr != nil {
				return nil, callErr
			}
			return nil, fmt.Errorf("EnumDeviceDrivers returned empty result")
		}

		if needed <= bufferBytes {
			count := int(needed) / size
			if count < 0 || count > len(bases) {
				count = len(bases)
			}
			return bases[:count], nil
		}

		capacity = int(needed)/size + 128
	}
}

func getWindowsDriverBaseName(base uintptr) string {
	buf := make([]uint16, windows.MAX_PATH)
	ret, _, _ := procGetDeviceDriverBaseNameW.Call(
		base,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	return strings.TrimSpace(windows.UTF16ToString(buf))
}

func getWindowsDriverPath(base uintptr) string {
	buf := make([]uint16, windows.MAX_PATH*2)
	ret, _, _ := procGetDeviceDriverFileNameW.Call(
		base,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	return strings.TrimSpace(windows.UTF16ToString(buf))
}

func normalizeWindowsDriverPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}

	trimmed = strings.TrimPrefix(trimmed, `\\?\`)
	trimmed = strings.TrimPrefix(trimmed, `\??\`)

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, `\systemroot\`) {
		if root := os.Getenv("SystemRoot"); root != "" {
			trimmed = filepath.Join(root, strings.TrimPrefix(trimmed, `\SystemRoot\`))
		}
	}

	if strings.HasPrefix(lower, `system32\`) {
		if root := os.Getenv("SystemRoot"); root != "" {
			trimmed = filepath.Join(root, strings.TrimPrefix(trimmed, `System32\`))
		}
	}

	return filepath.Clean(trimmed)
}

func windowsFileSize(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	return strconv.FormatInt(info.Size(), 10)
}

func fileVersionInfo(path string) (*string, *string) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	var handle windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &handle)
	if err != nil || size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return nil, nil
	}

	lang, code := getTranslation(buf)
	queryBase := `\StringFileInfo\` + lang + code + `\`
	version := queryVerValue(buf, queryBase+"ProductVersion")
	if version == nil {
		version = queryVerValue(buf, queryBase+"FileVersion")
	}
	description := queryVerValue(buf, queryBase+"FileDescription")
	return version, description
}

func getTranslation(buf []byte) (string, string) {
	var transPtr unsafe.Pointer
	var transLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&transPtr), &transLen); err != nil {
		return "0409", "04B0"
	}
	if transLen < 4 || transPtr == nil {
		return "0409", "04B0"
	}
	translations := (*[2]uint16)(transPtr)
	return formatHex(translations[0]), formatHex(translations[1])
}

func queryVerValue(buf []byte, path string) *string {
	var ptr unsafe.Pointer
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), path, unsafe.Pointer(&ptr), &length); err != nil {
		return nil
	}
	if ptr == nil {
		return nil
	}
	value := windows.UTF16PtrToString((*uint16)(ptr))
	return nullableString(value)
}

func formatHex(v uint16) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{
		hex[(v>>12)&0xF],
		hex[(v>>8)&0xF],
		hex[(v>>4)&0xF],
		hex[v&0xF],
	})
}
