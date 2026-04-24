package jarpackagescan

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"edrsystem/internal/processscan"
	"edrsystem/internal/webframescan"
)

func TestScanOutputSchemaAndDefaults(t *testing.T) {
	origWeb := scanWebFrameFn
	origProc := scanProcessFn
	scanWebFrameFn = func(ctx context.Context, params webframescan.WebFrameScanParams) (webframescan.WebFrameScanResult, error) {
		_ = ctx
		_ = params
		return webframescan.WebFrameScanResult{
			Rows: []webframescan.WebFrameRecord{
				{
					JarList: []webframescan.JarRecord{{JarName: strPtr("sample-1.0.0.jar")}},
				},
			},
		}, nil
	}
	scanProcessFn = func(ctx context.Context, params processscan.ProcessScanParams) ([]processscan.ProcessInfo, error) {
		_ = ctx
		_ = params
		return nil, nil
	}
	defer func() {
		scanWebFrameFn = origWeb
		scanProcessFn = origProc
	}()

	result, err := Scan(context.Background(), JarPackageScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 || len(result.Rows) != 1 {
		t.Fatalf("unexpected result size: total=%d rows=%d", result.Total, len(result.Rows))
	}
	row := result.Rows[0]
	if row.ExternalIPList == nil || row.InternalIPList == nil {
		t.Fatalf("expected list-based ip defaults")
	}
	if row.HostTagList == nil {
		t.Fatalf("expected hostTagList default []")
	}
	if row.Executable == nil {
		t.Fatalf("expected executable fallback")
	}
	if row.Type == nil {
		t.Fatalf("expected type fallback")
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	rowsAny, ok := decoded["rows"].([]any)
	if !ok || len(rowsAny) == 0 {
		t.Fatalf("expected rows array")
	}
	rowMap, ok := rowsAny[0].(map[string]any)
	if !ok {
		t.Fatalf("expected row object")
	}

	required := []string{
		"displayIp", "externalIpList", "internalIpList", "bizGroupId", "bizGroup", "remark", "hostTagList", "hostname",
		"name", "version", "type", "executable", "path",
	}
	for _, key := range required {
		if _, exists := rowMap[key]; !exists {
			t.Fatalf("missing key: %s", key)
		}
	}
	for _, forbidden := range []string{"riskLevel", "severity", "riskScore", "verdict", "alert"} {
		if _, exists := rowMap[forbidden]; exists {
			t.Fatalf("unexpected risk field: %s", forbidden)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	result := JarPackageScanResult{
		Total: 1,
		Rows: []JarPackageRecord{
			{Name: strPtr("sample.jar")},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("write json error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode written json: %v", err)
	}
	if got, ok := decoded["total"].(float64); !ok || int(got) != 1 {
		t.Fatalf("unexpected total in json output: %#v", decoded["total"])
	}
}
