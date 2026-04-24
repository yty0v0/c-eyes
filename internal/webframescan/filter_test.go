package webframescan

import "testing"

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []WebFrameRecord{
		{
			DisplayIP:      strPtr("10.10.10.5"),
			ExternalIPList: []string{"1.1.1.1"},
			InternalIPList: []string{"10.10.10.5"},
			BizGroupID:     int64Ptr(1001),
			Hostname:       strPtr("linux-web-01"),
			Name:           strPtr("nginx"),
			Version:        strPtr("1.24.0"),
			Type:           strPtr("php"),
			ServerName:     strPtr("nginx"),
		},
		{
			DisplayIP:      strPtr("192.168.56.10"),
			ExternalIPList: []string{"8.8.8.8"},
			InternalIPList: []string{"192.168.56.10"},
			BizGroupID:     int64Ptr(1002),
			Hostname:       strPtr("windows-app-01"),
			Name:           strPtr("tomcat"),
			Version:        strPtr("9.0.80"),
			Type:           strPtr("java"),
			ServerName:     strPtr("tomcat"),
		},
	}

	tests := []struct {
		name   string
		params WebFrameScanParams
		want   int
	}{
		{name: "no filters", params: WebFrameScanParams{}, want: 2},
		{name: "hostname fuzzy", params: WebFrameScanParams{Hostname: strPtr("linux")}, want: 1},
		{name: "ip fuzzy", params: WebFrameScanParams{IP: strPtr("192.168")}, want: 1},
		{name: "group exact", params: WebFrameScanParams{Groups: []int64{1001}}, want: 1},
		{name: "name fuzzy", params: WebFrameScanParams{Name: strPtr("tom")}, want: 1},
		{name: "version fuzzy", params: WebFrameScanParams{Version: strPtr("9.0")}, want: 1},
		{name: "type list", params: WebFrameScanParams{Type: []string{"java"}}, want: 1},
		{name: "server list", params: WebFrameScanParams{ServerName: []string{"nginx"}}, want: 1},
		{name: "combined", params: WebFrameScanParams{Hostname: strPtr("windows"), Type: []string{"java"}, ServerName: []string{"tom"}}, want: 1},
		{name: "combined mismatch", params: WebFrameScanParams{Hostname: strPtr("windows"), Type: []string{"php"}}, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyFilters(rows, tt.params)
			if len(got) != tt.want {
				t.Fatalf("expected %d rows, got %d", tt.want, len(got))
			}
		})
	}
}
