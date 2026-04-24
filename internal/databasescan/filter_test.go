package databasescan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	rows := []DatabaseRecord{
		{
			Name:     strPtr("MySQL"),
			Version:  strPtr("8.0"),
			Port:     intPtr(3306),
			ConfPath: strPtr("/etc/mysql/mysql.cnf"),
			LogPath:  strPtr("/var/log/mysql/error.log"),
			DataDir:  strPtr("/var/lib/mysql"),
		},
		{
			Name:     strPtr("MongoDB"),
			Version:  strPtr("6.0"),
			Port:     intPtr(27017),
			ConfPath: strPtr("/etc/mongod.conf"),
			LogPath:  strPtr("/var/log/mongodb/mongod.log"),
			DataDir:  strPtr("/var/lib/mongo"),
		},
	}

	host := processscan.HostInfo{
		Hostname:    "db-node-01",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params DatabaseScanParams
		want   int
	}{
		{name: "no filters", params: DatabaseScanParams{}, want: 2},
		{name: "name fuzzy", params: DatabaseScanParams{Name: strPtr("mysql")}, want: 1},
		{name: "version in list", params: DatabaseScanParams{Versions: []string{"6.0"}}, want: 1},
		{name: "port exact", params: DatabaseScanParams{Port: intPtr(27017)}, want: 1},
		{name: "conf path fuzzy", params: DatabaseScanParams{ConfPath: strPtr("mongod")}, want: 1},
		{name: "log path fuzzy", params: DatabaseScanParams{LogPath: strPtr("error")}, want: 1},
		{name: "data dir fuzzy", params: DatabaseScanParams{DataDir: strPtr("lib")}, want: 2},
		{name: "host filters match", params: DatabaseScanParams{Hostname: strPtr("node"), IP: strPtr("192.168"), Groups: []int64{39}}, want: 2},
		{name: "host group mismatch", params: DatabaseScanParams{Groups: []int64{88}}, want: 0},
		{name: "combined no match", params: DatabaseScanParams{Name: strPtr("mysql"), Port: intPtr(27017)}, want: 0},
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
