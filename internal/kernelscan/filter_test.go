package kernelscan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []KernelModuleInfo{
		{
			ModuleName: strPtr("nf_conntrack"),
			Path:       strPtr("/lib/modules/6.8.0/kernel/net/netfilter/nf_conntrack.ko"),
			Version:    strPtr("1.4"),
		},
		{
			ModuleName: strPtr("tcpip"),
			Path:       strPtr(`C:\Windows\System32\drivers\tcpip.sys`),
			Version:    strPtr("10.0.26100.1"),
		},
	}

	host := processscan.HostInfo{
		Hostname:    "node-alpha",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params KernelScanParams
		want   int
	}{
		{
			name: "match module name fuzzy",
			params: KernelScanParams{
				ModuleName: strPtr("conn"),
			},
			want: 1,
		},
		{
			name: "match path fuzzy",
			params: KernelScanParams{
				Path: strPtr("drivers"),
			},
			want: 1,
		},
		{
			name: "match version list",
			params: KernelScanParams{
				Version: []string{"10.0.26100.1"},
			},
			want: 1,
		},
		{
			name: "host filters match",
			params: KernelScanParams{
				Hostname: strPtr("alpha"),
				IP:       strPtr("192.168"),
				Groups:   []int64{39},
			},
			want: 2,
		},
		{
			name: "group mismatch",
			params: KernelScanParams{
				Groups: []int64{88},
			},
			want: 0,
		},
		{
			name: "combined row filters",
			params: KernelScanParams{
				ModuleName: strPtr("tcp"),
				Path:       strPtr("system32"),
				Version:    []string{"10.0.26100.1"},
			},
			want: 1,
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
