package portscan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []PortInfo{
		{
			Proto:       strPtr("tcp"),
			Port:        intPtr(22),
			BindIP:      strPtr("0.0.0.0"),
			ProcessName: strPtr("sshd"),
		},
		{
			Proto:       strPtr("tcp6"),
			Port:        intPtr(443),
			BindIP:      strPtr("::"),
			ProcessName: strPtr("nginx"),
		},
	}
	host := processscan.HostInfo{
		Hostname:    "node-alpha",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params PortScanParams
		want   int
	}{
		{
			name: "match by proto",
			params: PortScanParams{
				Protos: []string{"tcp6"},
			},
			want: 1,
		},
		{
			name: "match by port",
			params: PortScanParams{
				Port: intPtr(22),
			},
			want: 1,
		},
		{
			name: "match by bind ip",
			params: PortScanParams{
				BindIP: strPtr("0.0.0"),
			},
			want: 1,
		},
		{
			name: "match by process name fuzzy",
			params: PortScanParams{
				ProcessName: strPtr("ngin"),
			},
			want: 1,
		},
		{
			name: "match by host filters",
			params: PortScanParams{
				Hostname: strPtr("alpha"),
				IP:       strPtr("192.168"),
				Groups:   []int64{39},
			},
			want: 2,
		},
		{
			name: "biz group mismatch",
			params: PortScanParams{
				Groups: []int64{100},
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
