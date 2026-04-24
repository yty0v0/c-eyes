package environmentscan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []EnvironmentInfo{
		{
			Key:    strPtr("PATH"),
			Value:  strPtr("/usr/local/bin:/usr/bin"),
			User:   strPtr("root"),
			SysEnv: boolPtr(true),
		},
		{
			Key:    strPtr("TEMP"),
			Value:  strPtr(`C:\Windows\Temp`),
			User:   strPtr("Administrator"),
			SysEnv: boolPtr(false),
		},
	}

	host := processscan.HostInfo{
		Hostname:    "node-alpha",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params EnvironmentScanParams
		want   int
	}{
		{
			name: "no filters",
			params: EnvironmentScanParams{
				SysEnv: nil,
			},
			want: 2,
		},
		{
			name: "match key fuzzy",
			params: EnvironmentScanParams{
				Key: strPtr("pa"),
			},
			want: 1,
		},
		{
			name: "match value fuzzy",
			params: EnvironmentScanParams{
				Value: strPtr("windows"),
			},
			want: 1,
		},
		{
			name: "match user fuzzy",
			params: EnvironmentScanParams{
				User: strPtr("admin"),
			},
			want: 1,
		},
		{
			name: "match sysEnv array",
			params: EnvironmentScanParams{
				SysEnv: []bool{true},
			},
			want: 1,
		},
		{
			name: "combined row filters",
			params: EnvironmentScanParams{
				Key:    strPtr("te"),
				User:   strPtr("admin"),
				SysEnv: []bool{false},
			},
			want: 1,
		},
		{
			name: "host filters match",
			params: EnvironmentScanParams{
				Hostname: strPtr("alpha"),
				IP:       strPtr("192.168"),
				Groups:   []int64{39},
			},
			want: 2,
		},
		{
			name: "host filter mismatch",
			params: EnvironmentScanParams{
				Groups: []int64{88},
			},
			want: 0,
		},
		{
			name: "all conditions must match",
			params: EnvironmentScanParams{
				Key:    strPtr("temp"),
				Value:  strPtr("usr"),
				SysEnv: []bool{false},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyFilters(rows, tt.params, host)
			if len(got) != tt.want {
				t.Fatalf("expected %d records, got %d", tt.want, len(got))
			}
		})
	}
}
