package websitescan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []WebSiteInfo{
		{
			Type:  strPtr("nginx"),
			Port:  intPtr(443),
			Proto: strPtr("https"),
			Root:  &VirtualDirInfo{PhysicalPath: strPtr("/srv/www/app"), Root: boolPtr(true)},
		},
		{
			Type:  strPtr("tomcat"),
			Port:  intPtr(8080),
			Proto: strPtr("http"),
			Root:  &VirtualDirInfo{PhysicalPath: strPtr("/opt/tomcat/webapps"), Root: boolPtr(true)},
		},
	}
	host := processscan.HostInfo{
		Hostname:    "web-node-01",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params WebSiteScanParams
		want   int
	}{
		{name: "no filters", params: WebSiteScanParams{}, want: 2},
		{name: "port exact", params: WebSiteScanParams{Port: intPtr(443)}, want: 1},
		{name: "proto exact", params: WebSiteScanParams{Proto: strPtr("https")}, want: 1},
		{name: "type list", params: WebSiteScanParams{Type: []string{"tomcat"}}, want: 1},
		{name: "rootPath fuzzy", params: WebSiteScanParams{RootPath: strPtr("tomcat")}, want: 1},
		{name: "host filters match", params: WebSiteScanParams{Hostname: strPtr("web-node"), IP: strPtr("192.168"), Groups: []int64{39}}, want: 2},
		{name: "host group mismatch", params: WebSiteScanParams{Groups: []int64{99}}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyFilters(rows, tt.params, host)
			if len(got) != tt.want {
				t.Fatalf("expected %d rows, got %d", tt.want, len(got))
			}
		})
	}
}
