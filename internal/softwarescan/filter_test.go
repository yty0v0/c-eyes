package softwarescan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersHostAndRow(t *testing.T) {
	host := processscan.HostInfo{
		Hostname:    "node-a",
		InternalIPs: []string{"10.0.0.10"},
		ExternalIPs: []string{"203.0.113.10"},
		BizGroupID:  int64Ptr(39),
	}

	rows := []SoftwareInfo{
		{
			Name:       strPtr("nginx"),
			Version:    strPtr("1.24.0"),
			BinPath:    strPtr("/usr/sbin/nginx"),
			ConfigPath: strPtr("/etc/nginx/nginx.conf"),
		},
		{
			Name:       strPtr("apache"),
			Version:    strPtr("2.4.58"),
			BinPath:    strPtr("/usr/sbin/httpd"),
			ConfigPath: strPtr("/etc/httpd/conf/httpd.conf"),
		},
	}

	params := SoftwareScanParams{
		Groups:     []int64{39},
		Hostname:   strPtr("node"),
		IP:         strPtr("203.0.113"),
		Name:       strPtr("nginx"),
		Version:    []string{"1.24.0"},
		BinPath:    strPtr("nginx"),
		ConfigPath: strPtr("nginx.conf"),
	}

	filtered := ApplyFilters(rows, params, host)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 row, got %d", len(filtered))
	}
	if filtered[0].Name == nil || *filtered[0].Name != "nginx" {
		t.Fatalf("unexpected row: %+v", filtered[0])
	}
}

func TestApplyFiltersVersionListUsesExactFold(t *testing.T) {
	host := processscan.HostInfo{}
	rows := []SoftwareInfo{
		{Name: strPtr("nginx"), Version: strPtr("1.24.0")},
	}

	match := ApplyFilters(rows, SoftwareScanParams{Version: []string{"1.24.0"}}, host)
	if len(match) != 1 {
		t.Fatalf("expected exact version match")
	}

	noMatch := ApplyFilters(rows, SoftwareScanParams{Version: []string{"1.24"}}, host)
	if len(noMatch) != 0 {
		t.Fatalf("expected non-exact version to be rejected")
	}
}
