package accountscan

import (
	"io"
	"os"
)

func readLastlog(path string, entries []passwdEntry) map[int64]lastlogEntry {
	out := make(map[int64]lastlogEntry, len(entries))
	if len(entries) == 0 {
		return out
	}

	file, err := os.Open(path)
	if err != nil {
		return out
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil || stat.Size() == 0 {
		return out
	}

	recordSize := detectLastlogRecordSize(stat.Size())
	if recordSize <= 0 {
		return out
	}

	buf := make([]byte, recordSize)
	for _, entry := range entries {
		if entry.UID < 0 {
			continue
		}
		offset := entry.UID * int64(recordSize)
		if offset+int64(recordSize) > stat.Size() {
			continue
		}
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			continue
		}
		if _, err := io.ReadFull(file, buf); err != nil {
			continue
		}
		record := parseLastlogRecord(buf)
		if record.Time == nil {
			continue
		}
		out[entry.UID] = record
	}
	return out
}

func detectLastlogRecordSize(fileSize int64) int {
	candidates := []int{296, 292}
	for _, c := range candidates {
		if fileSize%int64(c) == 0 {
			return c
		}
	}
	return candidates[0]
}
