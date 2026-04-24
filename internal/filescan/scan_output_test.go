package filescan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileScanOutputFields(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "sample.bin")
	data := bytes.Repeat([]byte("A"), 5000)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if runtime.GOOS == "windows" {
		zone := "[ZoneTransfer]\nZoneId=3\nHostUrl=http://example.com/\n"
		_ = os.WriteFile(path+":Zone.Identifier", []byte(zone), 0o644)
	}

	results, err := Scan(context.Background(), FileScanParams{
		Mode:       ScanModePath,
		Path:       tmp,
		MaxTargets: 10,
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	var found *FileScanResult
	for i := range results {
		res := &results[i]
		if res.BasicInfo != nil && res.BasicInfo.FilePath != nil && *res.BasicInfo.FilePath == path {
			found = res
			break
		}
	}
	if found == nil {
		t.Fatalf("expected scan result for %s", path)
	}

	if found.BasicInfo == nil || found.BasicInfo.FileName == nil || *found.BasicInfo.FileName != "sample.bin" {
		t.Fatalf("unexpected file name: %+v", found.BasicInfo)
	}
	if found.SmartEnabled == nil || *found.SmartEnabled {
		t.Fatalf("expected smart_enabled=false for plain path scan, got %+v", found.SmartEnabled)
	}
	if found.BasicInfo.FileSizeBytes == nil || *found.BasicInfo.FileSizeBytes != int64(len(data)) {
		t.Fatalf("unexpected file size: %+v", found.BasicInfo)
	}
	if found.BasicInfo.ModificationTime == nil {
		t.Fatalf("expected modification_time")
	}

	if found.Hashes == nil || found.Hashes.Sha256 == nil {
		t.Fatalf("expected sha256")
	}
	shaSum := sha256.Sum256(data)
	if *found.Hashes.Sha256 != hex.EncodeToString(shaSum[:]) {
		t.Fatalf("sha256 mismatch: %s", *found.Hashes.Sha256)
	}
	if found.Hashes.Imphash != nil {
		t.Fatalf("expected imphash nil for non-PE file")
	}

	if found.BinaryInfo != nil {
		t.Fatalf("expected binary_info nil for non-PE/ELF file")
	}

	if runtime.GOOS == "windows" {
		if found.Context == nil || found.Context.MotwZoneID == nil || *found.Context.MotwZoneID != 3 {
			t.Fatalf("expected motw zone id")
		}
		if found.Context.DownloadURL == nil || *found.Context.DownloadURL == "" {
			t.Fatalf("expected download url")
		}
	} else if found.Context != nil {
		t.Fatalf("expected context nil on non-windows")
	}
}
