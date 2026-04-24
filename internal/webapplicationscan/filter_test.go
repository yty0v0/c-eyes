package webapplicationscan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []WebApplicationInfo{
		{
			AppName:     strPtr("nginx"),
			ServerName:  strPtr("nginx"),
			Version:     strPtr("1.24.0"),
			RootPath:    strPtr("/etc/nginx/nginx.conf"),
			WebRoot:     strPtr("/var/www/html"),
			DomainName:  strPtr("example.com"),
			PluginCount: intPtr(1),
			Plugins: []PluginInfo{
				{PluginName: strPtr("ngx_http_geoip_module.so")},
			},
		},
		{
			AppName:     strPtr("tomcat"),
			ServerName:  strPtr("tomcat"),
			Version:     strPtr("9.0.80"),
			RootPath:    strPtr("/opt/tomcat/conf/server.xml"),
			WebRoot:     strPtr("/opt/tomcat/webapps"),
			DomainName:  strPtr("localhost"),
			PluginCount: intPtr(0),
			Plugins:     []PluginInfo{},
		},
	}

	host := processscan.HostInfo{
		Hostname:    "web-node-01",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params WebApplicationScanParams
		want   int
	}{
		{name: "no filters", params: WebApplicationScanParams{}, want: 2},
		{name: "app name fuzzy", params: WebApplicationScanParams{AppName: strPtr("ngi")}, want: 1},
		{name: "version list", params: WebApplicationScanParams{Version: []string{"9.0.80"}}, want: 1},
		{name: "server array", params: WebApplicationScanParams{ServerName: []string{"tomcat"}}, want: 1},
		{name: "root path fuzzy", params: WebApplicationScanParams{RootPath: strPtr("server.xml")}, want: 1},
		{name: "web root fuzzy", params: WebApplicationScanParams{WebRoot: strPtr("webapps")}, want: 1},
		{name: "domain fuzzy", params: WebApplicationScanParams{DomainName: strPtr("example")}, want: 1},
		{name: "host filters match", params: WebApplicationScanParams{Hostname: strPtr("web-node"), IP: strPtr("192.168"), Groups: []int64{39}}, want: 2},
		{name: "host group mismatch", params: WebApplicationScanParams{Groups: []int64{99}}, want: 0},
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
