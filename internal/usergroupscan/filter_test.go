package usergroupscan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	groups := []UserGroupInfo{
		{
			Name: strPtr("developers"),
			GID:  int64Ptr(1000),
		},
		{
			Name: strPtr("admins"),
			GID:  int64Ptr(1001),
		},
	}
	host := processscan.HostInfo{
		Hostname:    "node-alpha",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params UserGroupScanParams
		want   int
	}{
		{
			name: "match by group name fuzzy",
			params: UserGroupScanParams{
				Name: strPtr("dev"),
			},
			want: 1,
		},
		{
			name: "match by gid",
			params: UserGroupScanParams{
				GID: int64Ptr(1001),
			},
			want: 1,
		},
		{
			name: "match by host name",
			params: UserGroupScanParams{
				Hostname: strPtr("alpha"),
			},
			want: 2,
		},
		{
			name: "match by host ip",
			params: UserGroupScanParams{
				IP: strPtr("192.168"),
			},
			want: 2,
		},
		{
			name: "match by biz group",
			params: UserGroupScanParams{
				Groups: []int64{39},
			},
			want: 2,
		},
		{
			name: "biz group mismatch",
			params: UserGroupScanParams{
				Groups: []int64{88},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyFilters(groups, tt.params, host)
			if len(got) != tt.want {
				t.Fatalf("expected %d records, got %d", tt.want, len(got))
			}
		})
	}
}
