//go:build windows

package filescan

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fsctlQueryUsnJournal = 0x000900f4
	fsctlReadUsnJournal  = 0x000900bb

	usnReasonDataOverwrite  = 0x00000001
	usnReasonDataExtend     = 0x00000002
	usnReasonDataTruncation = 0x00000004
	usnReasonFileCreate     = 0x00000100
	usnReasonFileDelete     = 0x00000200
	usnReasonRenameNewName  = 0x00002000
	usnReasonRenameOldName  = 0x00001000
	usnReasonClose          = 0x80000000

	fileAttributeDirectory = 0x00000010
)

type usnJournalDataV0 struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type readUsnJournalData struct {
	StartUsn          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
}

func collectRecentPlatform(ctx context.Context, params FileScanParams, since time.Time) ([]ScanTask, bool, error) {
	tasks, err := collectRecentUSN(ctx, since, normalizeSmartMaxTargets(params.MaxTargets))
	if err != nil {
		return nil, false, nil
	}
	if len(tasks) == 0 {
		return nil, false, nil
	}
	return tasks, true, nil
}

func collectRecentUSN(ctx context.Context, since time.Time, limit int) ([]ScanTask, error) {
	roots := listRoots()
	if len(roots) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = normalizeSmartMaxTargets(0)
	}

	var tasks []ScanTask
	for _, root := range roots {
		select {
		case <-ctx.Done():
			return tasks, ctx.Err()
		default:
		}
		vol := strings.TrimSuffix(root, `\`)
		handle, err := openVolumeHandle(vol)
		if err != nil {
			continue
		}
		journal, err := queryUsnJournal(handle)
		if err != nil {
			windows.CloseHandle(handle)
			continue
		}
		collected := collectRecentUSNFromVolume(ctx, handle, journal, since, limit-len(tasks))
		tasks = append(tasks, collected...)
		windows.CloseHandle(handle)
		if len(tasks) >= limit {
			break
		}
	}
	return dedupeTasks(tasks), nil
}

func openVolumeHandle(root string) (windows.Handle, error) {
	vol := strings.TrimSuffix(root, `\`)
	path := `\\.\` + vol
	return windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
}

func queryUsnJournal(handle windows.Handle) (usnJournalDataV0, error) {
	var data usnJournalDataV0
	var returned uint32
	err := windows.DeviceIoControl(handle, fsctlQueryUsnJournal, nil, 0, (*byte)(unsafe.Pointer(&data)), uint32(unsafe.Sizeof(data)), &returned, nil)
	return data, err
}

func collectRecentUSNFromVolume(ctx context.Context, handle windows.Handle, journal usnJournalDataV0, since time.Time, limit int) []ScanTask {
	if limit <= 0 {
		return nil
	}
	readData := readUsnJournalData{
		StartUsn:          journal.FirstUsn,
		ReasonMask:        usnReasonDataOverwrite | usnReasonDataExtend | usnReasonDataTruncation | usnReasonFileCreate | usnReasonRenameNewName | usnReasonRenameOldName | usnReasonClose | usnReasonFileDelete,
		ReturnOnlyOnClose: 0,
		Timeout:           0,
		BytesToWaitFor:    0,
		UsnJournalID:      journal.UsnJournalID,
	}

	buf := make([]byte, 1<<20)
	tasks := make([]ScanTask, 0, limit)
	for readData.StartUsn < journal.NextUsn && len(tasks) < limit {
		select {
		case <-ctx.Done():
			return tasks
		default:
		}
		var returned uint32
		err := windows.DeviceIoControl(handle, fsctlReadUsnJournal, (*byte)(unsafe.Pointer(&readData)), uint32(unsafe.Sizeof(readData)), &buf[0], uint32(len(buf)), &returned, nil)
		if err != nil || returned <= 8 {
			break
		}
		nextUsn := int64(binary.LittleEndian.Uint64(buf[:8]))
		offset := 8
		for offset+60 <= int(returned) {
			recordLen := int(binary.LittleEndian.Uint32(buf[offset:]))
			if recordLen <= 0 || offset+recordLen > int(returned) {
				break
			}
			rec := buf[offset : offset+recordLen]
			timestamp := int64(binary.LittleEndian.Uint64(rec[32:40]))
			if filetimeToTime(timestamp).Before(since) {
				offset += recordLen
				continue
			}
			fileAttrs := binary.LittleEndian.Uint32(rec[52:56])
			if fileAttrs&fileAttributeDirectory != 0 {
				offset += recordLen
				continue
			}
			nameLen := int(binary.LittleEndian.Uint16(rec[56:58]))
			nameOff := int(binary.LittleEndian.Uint16(rec[58:60]))
			if nameOff+nameLen > len(rec) || nameLen == 0 {
				offset += recordLen
				continue
			}
			name := decodeUTF16(rec[nameOff : nameOff+nameLen])
			if !isInterestingExtension(name) {
				offset += recordLen
				continue
			}
			frn := binary.LittleEndian.Uint64(rec[8:16])
			path, err := openFilePathByID(handle, frn)
			if err == nil && path != "" {
				tasks = append(tasks, ScanTask{
					Path:   path,
					Source: SourceRecent,
					Mode:   ScanModeSmart,
				})
				if len(tasks) >= limit {
					break
				}
			}
			offset += recordLen
		}
		if nextUsn <= readData.StartUsn {
			break
		}
		readData.StartUsn = nextUsn
	}
	return tasks
}

func decodeUTF16(buf []byte) string {
	if len(buf)%2 != 0 {
		buf = buf[:len(buf)-1]
	}
	u16 := make([]uint16, len(buf)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return string(utf16.Decode(u16))
}

func filetimeToTime(filetime int64) time.Time {
	const ticks = 10000000
	const epochDiff = 11644473600
	sec := filetime / ticks
	nsec := (filetime % ticks) * 100
	return time.Unix(sec-epochDiff, nsec)
}

const (
	fileIdType = 0
)

type fileIDDescriptor struct {
	Size   uint32
	Type   uint32
	FileID [16]byte
}

var (
	kernel32Usn              = windows.NewLazySystemDLL("kernel32.dll")
	procOpenFileById         = kernel32Usn.NewProc("OpenFileById")
	procGetFinalPathByHandle = kernel32Usn.NewProc("GetFinalPathNameByHandleW")
)

func openFilePathByID(volume windows.Handle, frn uint64) (string, error) {
	var desc fileIDDescriptor
	desc.Size = uint32(unsafe.Sizeof(desc))
	desc.Type = fileIdType
	binary.LittleEndian.PutUint64(desc.FileID[:8], frn)

	handle, _, err := procOpenFileById.Call(
		uintptr(volume),
		uintptr(unsafe.Pointer(&desc)),
		uintptr(windows.GENERIC_READ),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE),
		0,
		uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS),
	)
	if handle == 0 {
		return "", err
	}
	defer windows.CloseHandle(windows.Handle(handle))

	buf := make([]uint16, windows.MAX_PATH)
	n, _, err := procGetFinalPathByHandle.Call(handle, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if n == 0 {
		return "", err
	}
	path := windows.UTF16ToString(buf[:n])
	return cleanWinPath(path), nil
}

func cleanWinPath(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	}
	if strings.HasPrefix(path, `\\?\`) {
		return strings.TrimPrefix(path, `\\?\`)
	}
	return filepath.Clean(path)
}
