//go:build windows

package startupscan

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type windowsServiceRecord struct {
	Name       string
	Display    string
	User       string
	State      uint32
	StartType  int
	BinaryPath string
}

type windowsServiceCollector interface {
	Collect(ctx context.Context) ([]windowsServiceRecord, error)
}

type nativeWindowsServiceCollector struct{}

var windowsServiceCollectorProvider = func() windowsServiceCollector {
	return &nativeWindowsServiceCollector{}
}

var resolvePublisherFn = publisherFromBinaryPath

func collectStartupItems(ctx context.Context) ([]StartupInfo, error) {
	records, err := windowsServiceCollectorProvider().Collect(ctx)
	if err != nil {
		return nil, err
	}

	rows := make([]StartupInfo, 0, len(records))
	for _, rec := range records {
		row := StartupInfo{
			Name:      nullableString(rec.Name),
			ShowName:  nullableString(rec.Display),
			User:      nullableString(rec.User),
			Enable:    boolPtr(rec.State == uint32(svc.Running)),
			StartType: intPtr(rec.StartType),
			Xinetd:    boolPtr(false),
		}

		row.DefaultOpen = boolPtr(defaultOpenFromStartType(rec.StartType))
		if execPath := extractExecutablePath(rec.BinaryPath); execPath != "" {
			row.ExecPath = strPtr(execPath)
		}
		if publisher := resolvePublisherFn(rec.BinaryPath); publisher != "" {
			row.Publisher = strPtr(publisher)
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		li := ""
		if rows[i].Name != nil {
			li = strings.ToLower(*rows[i].Name)
		}
		lj := ""
		if rows[j].Name != nil {
			lj = strings.ToLower(*rows[j].Name)
		}
		return li < lj
	})

	return rows, nil
}

func (c *nativeWindowsServiceCollector) Collect(ctx context.Context) ([]windowsServiceRecord, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer manager.Disconnect()

	names, err := manager.ListServices()
	if err != nil {
		return nil, err
	}

	out := make([]windowsServiceRecord, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		svcHandle, err := manager.OpenService(name)
		if err != nil {
			continue
		}

		record := windowsServiceRecord{Name: name}
		if cfg, err := svcHandle.Config(); err == nil {
			record.Display = strings.TrimSpace(cfg.DisplayName)
			record.User = strings.TrimSpace(cfg.ServiceStartName)
			record.StartType = int(cfg.StartType)
			record.BinaryPath = strings.TrimSpace(cfg.BinaryPathName)
		}
		if status, err := svcHandle.Query(); err == nil {
			record.State = uint32(status.State)
		}
		_ = svcHandle.Close()

		out = append(out, record)
	}
	return out, nil
}

func defaultOpenFromStartType(startType int) bool {
	switch uint32(startType) {
	case windows.SERVICE_BOOT_START, windows.SERVICE_SYSTEM_START, windows.SERVICE_AUTO_START:
		return true
	default:
		return false
	}
}

func publisherFromBinaryPath(path string) string {
	executable := extractExecutablePath(path)
	if executable == "" {
		return ""
	}
	_, company := fileVersionInfo(executable)
	if company == nil {
		return ""
	}
	return strings.TrimSpace(*company)
}

func extractExecutablePath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	var path string
	if strings.HasPrefix(trimmed, "\"") {
		rest := strings.TrimPrefix(trimmed, "\"")
		end := strings.Index(rest, "\"")
		if end < 0 {
			path = rest
		} else {
			path = rest[:end]
		}
	} else {
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			return ""
		}
		path = fields[0]
	}

	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, `\??\`)
	path = expandPercentEnv(path)
	if strings.HasPrefix(strings.ToLower(path), `\systemroot\`) {
		if root := os.Getenv("SystemRoot"); root != "" {
			path = root + path[len(`\systemroot`):]
		}
	}
	return filepath.Clean(path)
}

func expandPercentEnv(input string) string {
	out := input
	for {
		start := strings.Index(out, "%")
		if start < 0 {
			return out
		}
		end := strings.Index(out[start+1:], "%")
		if end < 0 {
			return out
		}
		end = start + 1 + end
		key := out[start+1 : end]
		if key == "" {
			return out
		}
		value := os.Getenv(key)
		out = out[:start] + value + out[end+1:]
	}
}

func fileVersionInfo(path string) (*string, *string) {
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
	queryBase := "\\StringFileInfo\\" + lang + code + "\\"

	version := queryVerValue(buf, queryBase+"ProductVersion")
	if version == nil {
		version = queryVerValue(buf, queryBase+"FileVersion")
	}
	company := queryVerValue(buf, queryBase+"CompanyName")
	return version, company
}

func getTranslation(buf []byte) (string, string) {
	var transPtr unsafe.Pointer
	var transLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), "\\VarFileInfo\\Translation", unsafe.Pointer(&transPtr), &transLen); err != nil {
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
	if value == "" {
		return nil
	}
	return strPtr(value)
}

func formatHex(value uint16) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{
		hex[(value>>12)&0xF],
		hex[(value>>8)&0xF],
		hex[(value>>4)&0xF],
		hex[value&0xF],
	})
}
