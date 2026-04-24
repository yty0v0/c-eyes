package filescan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFileScanResultJSONTags(t *testing.T) {
	path := "/tmp/sample"
	result := FileScanResult{
		ScanResult: scanResultPtr(ScanResultSafe),
		BasicInfo: &FileBasicInfo{
			FilePath: &path,
		},
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	jsonStr := string(payload)
	for _, key := range []string{`"basic_info"`, `"file_path"`} {
		if !strings.Contains(jsonStr, key) {
			t.Fatalf("expected JSON to contain %s", key)
		}
	}
	for _, key := range []string{`"scan_result"`, `"last_scan_time"`} {
		if strings.Contains(jsonStr, key) {
			t.Fatalf("expected JSON to omit %s", key)
		}
	}
}
