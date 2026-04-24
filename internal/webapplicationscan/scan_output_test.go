package webapplicationscan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestScanOutputIncludesTotalRowsAndDefaults(t *testing.T) {
	orig := collectWebApplicationsFn
	origAssoc := enableProcessAssociation
	enableProcessAssociation = false
	collectWebApplicationsFn = func(ctx context.Context) ([]WebApplicationInfo, error) {
		_ = ctx
		return []WebApplicationInfo{
			{
				AppName:    strPtr("nginx"),
				ServerName: strPtr("nginx"),
				Plugins: []PluginInfo{
					{PluginName: strPtr("  ngx_http_image_filter_module.so  ")},
				},
			},
		}, nil
	}
	defer func() {
		collectWebApplicationsFn = orig
		enableProcessAssociation = origAssoc
	}()

	result, err := Scan(context.Background(), WebApplicationScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
	}
	row := result.Rows[0]
	if row.HostTagList == nil {
		t.Fatalf("expected hostTagList default []")
	}
	if row.ExternalIPList == nil {
		t.Fatalf("expected externalIpList default []")
	}
	if row.InternalIPList == nil {
		t.Fatalf("expected internalIpList default []")
	}
	if row.Plugins == nil {
		t.Fatalf("expected plugins default []")
	}
	if row.PluginCount == nil || *row.PluginCount != 1 {
		t.Fatalf("expected pluginCount=1, got %+v", row.PluginCount)
	}
	if row.Plugins[0].PluginName == nil || *row.Plugins[0].PluginName != "ngx_http_image_filter_module.so" {
		t.Fatalf("expected normalized pluginName, got %+v", row.Plugins[0].PluginName)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if _, ok := decoded["total"]; !ok {
		t.Fatalf("missing total key")
	}
	if _, ok := decoded["rows"]; !ok {
		t.Fatalf("missing rows key")
	}
}
