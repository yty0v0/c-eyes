package startupscan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []StartupInfo{
		{
			Name:        strPtr("sshd"),
			DefaultOpen: boolPtr(true),
			InitLevel:   intPtr(3),
			Xinetd:      boolPtr(false),
		},
		{
			Name:        strPtr("telnet"),
			DefaultOpen: boolPtr(false),
			InitLevel:   intPtr(5),
			Xinetd:      boolPtr(true),
			ShowName:    strPtr("Telnet Service"),
			User:        strPtr("LocalSystem"),
			Enable:      boolPtr(true),
			StartType:   intPtr(2),
			Publisher:   strPtr("Microsoft Corporation"),
		},
	}

	host := processscan.HostInfo{
		Hostname:    "node-alpha",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params StartupScanParams
		want   int
	}{
		{
			name: "match by linux startup name",
			params: StartupScanParams{
				Name: strPtr("ssh"),
			},
			want: 1,
		},
		{
			name: "match by init level",
			params: StartupScanParams{
				InitLevel: []int{5},
			},
			want: 1,
		},
		{
			name: "match by defaultOpen",
			params: StartupScanParams{
				DefaultOpen: []bool{true},
			},
			want: 1,
		},
		{
			name: "match by xinetd flag",
			params: StartupScanParams{
				IsXinetd: []bool{true},
			},
			want: 1,
		},
		{
			name: "match by windows fields",
			params: StartupScanParams{
				ShowName:  strPtr("telnet"),
				User:      strPtr("localsystem"),
				Enable:    boolPtr(true),
				StartType: []int{2},
				Publisher: strPtr("microsoft"),
			},
			want: 1,
		},
		{
			name: "match by host filters",
			params: StartupScanParams{
				Hostname: strPtr("alpha"),
				IP:       strPtr("192.168"),
				Groups:   []int64{39},
			},
			want: 2,
		},
		{
			name: "biz group mismatch",
			params: StartupScanParams{
				Groups: []int64{88},
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
