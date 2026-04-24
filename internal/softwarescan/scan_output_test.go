package softwarescan

import (
	"context"
	"encoding/json"
	"testing"

	"edrsystem/internal/processscan"
)

func TestScanOutputSchemaAndDefaults(t *testing.T) {
	origCollect := collectSoftwareFn
	origHost := getHostInfoFn
	collectSoftwareFn = func(ctx context.Context) ([]SoftwareInfo, error) {
		_ = ctx
		return []SoftwareInfo{
			{
				Name:    strPtr("nginx"),
				BinPath: strPtr("/usr/sbin/nginx"),
				Processes: []SoftwareProcess{
					{PID: intPtr(101), Name: strPtr("nginx"), Uname: strPtr("root")},
				},
			},
		}, nil
	}
	getHostInfoFn = func() (processscan.HostInfo, error) {
		return processscan.HostInfo{
			Hostname:    "node-a",
			InternalIPs: []string{"10.0.0.10"},
			ExternalIPs: []string{"203.0.113.10"},
			BizGroupID:  int64Ptr(7),
			BizGroup:    strPtr("default"),
			Remark:      strPtr("remark"),
			HostTagList: []string{"prod"},
		}, nil
	}
	defer func() {
		collectSoftwareFn = origCollect
		getHostInfoFn = origHost
	}()

	result, err := Scan(context.Background(), SoftwareScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 || len(result.Rows) != 1 {
		t.Fatalf("unexpected result size: total=%d rows=%d", result.Total, len(result.Rows))
	}
	row := result.Rows[0]
	if row.ExternalIPList == nil || row.InternalIPList == nil {
		t.Fatalf("expected list-based IP defaults")
	}
	if row.HostTagList == nil {
		t.Fatalf("expected hostTagList default []")
	}
	if row.Processes == nil {
		t.Fatalf("expected processes default []")
	}
	if row.Hostname == nil || *row.Hostname != "node-a" {
		t.Fatalf("expected host enrichment")
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
		"externalIpList", "internalIpList", "bizGroupId", "bizGroup", "remark", "hostTagList", "hostname",
		"name", "version", "uname", "binPath", "configPath", "processes",
	}
	for _, key := range required {
		if _, exists := rowMap[key]; !exists {
			t.Fatalf("missing key: %s", key)
		}
	}
	for _, forbidden := range []string{
		"displayIp", "externalIp", "internalIp",
		"riskLevel", "severity", "riskScore", "verdict", "alert",
	} {
		if _, exists := rowMap[forbidden]; exists {
			t.Fatalf("unexpected field in output: %s", forbidden)
		}
	}
}
