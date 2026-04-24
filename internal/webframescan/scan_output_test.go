package webframescan

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"edrsystem/internal/webapplicationscan"
)

func TestScanOutputSchemaAndDefaults(t *testing.T) {
	orig := scanWebApplicationsFn
	scanWebApplicationsFn = func(ctx context.Context, params webapplicationscan.WebApplicationScanParams) (webapplicationscan.WebApplicationScanResult, error) {
		_ = ctx
		_ = params
		return webapplicationscan.WebApplicationScanResult{
			Rows: []webapplicationscan.WebApplicationInfo{
				{
					AppName:    strPtr("nginx"),
					ServerName: strPtr("nginx"),
					Plugins: []webapplicationscan.PluginInfo{
						{PluginName: strPtr("sample-1.0.0.jar")},
					},
				},
			},
		}, nil
	}
	defer func() { scanWebApplicationsFn = orig }()

	result, err := Scan(context.Background(), WebFrameScanParams{})
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
	if row.JarList == nil {
		t.Fatalf("expected jarList default []")
	}
	if row.JarCount == nil || *row.JarCount != "1" {
		t.Fatalf("expected jarCount=1, got %+v", row.JarCount)
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
		"name", "version", "type", "serverName", "domainName", "webAppDir", "jarCount", "jarList", "webRoot", "workDir",
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

	jarListAny, ok := rowMap["jarList"].([]any)
	if !ok || len(jarListAny) != 1 {
		t.Fatalf("expected jarList array with one item")
	}
	jarMap, ok := jarListAny[0].(map[string]any)
	if !ok {
		t.Fatalf("expected jarList item object")
	}
	for _, key := range []string{"version", "absDir", "jarName"} {
		if _, exists := jarMap[key]; !exists {
			t.Fatalf("jarList item missing key: %s", key)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	result := WebFrameScanResult{
		Total: 1,
		Rows: []WebFrameRecord{
			{Name: strPtr("nginx"), JarList: []JarRecord{}},
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
