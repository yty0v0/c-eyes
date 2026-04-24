package jarpackagescan

import "testing"

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []JarPackageRecord{
		{
			DisplayIP:      strPtr("10.10.10.5"),
			ExternalIPList: []string{"1.1.1.1"},
			InternalIPList: []string{"10.10.10.5"},
			BizGroupID:     int64Ptr(1001),
			Hostname:       strPtr("linux-web-01"),
			Name:           strPtr("spring-core-6.1.2.jar"),
			Version:        strPtr("6.1.2"),
			Type:           intPtr(3),
			Executable:     boolPtr(false),
			Path:           strPtr("/opt/tomcat/lib/spring-core-6.1.2.jar"),
		},
		{
			DisplayIP:      strPtr("192.168.56.10"),
			ExternalIPList: []string{"8.8.8.8"},
			InternalIPList: []string{"192.168.56.10"},
			BizGroupID:     int64Ptr(1002),
			Hostname:       strPtr("windows-app-01"),
			Name:           strPtr("bootstrap-3.0.0.jar"),
			Version:        strPtr("3.0.0"),
			Type:           intPtr(1),
			Executable:     boolPtr(true),
			Path:           strPtr(`C:\apps\bootstrap-3.0.0.jar`),
		},
	}

	tests := []struct {
		name   string
		params JarPackageScanParams
		want   int
	}{
		{name: "no filters", params: JarPackageScanParams{}, want: 2},
		{name: "hostname fuzzy", params: JarPackageScanParams{Hostname: strPtr("linux")}, want: 1},
		{name: "ip fuzzy", params: JarPackageScanParams{IP: strPtr("192.168")}, want: 1},
		{name: "group exact", params: JarPackageScanParams{Groups: []int64{1001}}, want: 1},
		{name: "name fuzzy", params: JarPackageScanParams{Name: strPtr("spring")}, want: 1},
		{name: "version list", params: JarPackageScanParams{Version: []string{"3.0"}}, want: 1},
		{name: "type list", params: JarPackageScanParams{Type: []int{3}}, want: 1},
		{name: "executable list", params: JarPackageScanParams{Executable: []bool{true}}, want: 1},
		{name: "path fuzzy", params: JarPackageScanParams{Path: strPtr("tomcat/lib")}, want: 1},
		{name: "combined", params: JarPackageScanParams{Hostname: strPtr("windows"), Type: []int{1}, Executable: []bool{true}}, want: 1},
		{name: "combined mismatch", params: JarPackageScanParams{Hostname: strPtr("windows"), Type: []int{3}}, want: 0},
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
