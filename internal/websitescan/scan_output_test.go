package websitescan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestScanOutputIncludesTotalRowsAndDefaults(t *testing.T) {
	orig := collectWebSitesFn
	origAssoc := enableWebSiteProcessAssociation
	enableWebSiteProcessAssociation = false
	collectWebSitesFn = func(ctx context.Context) ([]WebSiteInfo, error) {
		_ = ctx
		return []WebSiteInfo{{
			Type:       strPtr("nginx"),
			Domains:    []DomainInfo{{Name: strPtr(" example.com ")}},
			VirtualDir: []VirtualDirInfo{{Path: strPtr("/"), PhysicalPath: strPtr("/var/www/html"), Root: boolPtr(true)}},
		}}, nil
	}
	defer func() {
		collectWebSitesFn = orig
		enableWebSiteProcessAssociation = origAssoc
	}()

	result, err := Scan(context.Background(), WebSiteScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	row := result.Rows[0]
	if row.HostTagList == nil || row.ExternalIPList == nil || row.InternalIPList == nil {
		t.Fatalf("expected default host/ip arrays")
	}
	if row.Domains == nil || row.VirtualDir == nil {
		t.Fatalf("expected default nested arrays")
	}
	if row.PortStatus == nil || *row.PortStatus != -1 {
		t.Fatalf("expected default portStatus=-1")
	}
	if row.BindingCount == nil || *row.BindingCount != 1 {
		t.Fatalf("expected bindingCount=1")
	}
	if row.VirtualDirCount == nil || *row.VirtualDirCount != 1 {
		t.Fatalf("expected virtualDirCount=1")
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
