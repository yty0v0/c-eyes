package accountscan

import (
	"testing"
	"time"

	"edrsystem/internal/processscan"
)

func TestApplyFilters_TableDriven(t *testing.T) {
	now := time.Now()
	accounts := []AccountInfo{
		{
			Name:          strPtr("root"),
			UID:           int64Ptr(0),
			GID:           int64Ptr(0),
			Home:          strPtr("/root"),
			Status:        intPtr(1),
			LastLoginTime: &now,
		},
		{
			Name:          strPtr("daemon"),
			UID:           int64Ptr(1),
			GID:           int64Ptr(1),
			Home:          strPtr("/usr/sbin"),
			Status:        intPtr(0),
			LastLoginTime: nil,
		},
	}
	host := processscan.HostInfo{
		Hostname:    "node-alpha",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params AccountScanParams
		want   int
	}{
		{
			name: "match by name fuzzy",
			params: AccountScanParams{
				Name: strPtr("roo"),
			},
			want: 1,
		},
		{
			name: "match by uid",
			params: AccountScanParams{
				UID: int64Ptr(1),
			},
			want: 1,
		},
		{
			name: "match by gid",
			params: AccountScanParams{
				GID: int64Ptr(0),
			},
			want: 1,
		},
		{
			name: "match by status list",
			params: AccountScanParams{
				Status: []int{0},
			},
			want: 1,
		},
		{
			name: "match by host",
			params: AccountScanParams{
				Hostname: strPtr("alpha"),
			},
			want: 2,
		},
		{
			name: "match by ip",
			params: AccountScanParams{
				IP: strPtr("192.168"),
			},
			want: 2,
		},
		{
			name: "match by biz group",
			params: AccountScanParams{
				Groups: []int64{39},
			},
			want: 2,
		},
		{
			name: "match by login time",
			params: AccountScanParams{
				LastLoginTime: &DateRange{
					From: timePtr(now.Add(-time.Hour)),
					To:   timePtr(now.Add(time.Hour)),
				},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyFilters(accounts, tt.params, host)
			if len(got) != tt.want {
				t.Fatalf("expected %d results, got %d", tt.want, len(got))
			}
		})
	}
}

func timePtr(v time.Time) *time.Time {
	return &v
}
