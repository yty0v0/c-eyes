package softwarescan

import "testing"

func TestMergeRowsAggregatesProcessesAndPaths(t *testing.T) {
	rows := []SoftwareInfo{
		{
			Name:       strPtr("nginx"),
			BinPath:    strPtr("/usr/sbin/nginx"),
			ConfigPath: strPtr("/etc/nginx/nginx.conf"),
			Processes: []SoftwareProcess{
				{PID: intPtr(101), Name: strPtr("nginx"), Uname: strPtr("root")},
			},
			ExternalIPList: []string{"203.0.113.10"},
		},
		{
			Name:       strPtr("nginx"),
			BinPath:    strPtr("/usr/sbin/nginx"),
			ConfigPath: strPtr("/etc/nginx/nginx.conf"),
			Processes: []SoftwareProcess{
				{PID: intPtr(102), Name: strPtr("nginx"), Uname: strPtr("www-data")},
			},
			InternalIPList: []string{"10.0.0.10"},
		},
	}

	merged := mergeRows(rows)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged row, got %d", len(merged))
	}
	row := merged[0]
	if len(row.Processes) != 2 {
		t.Fatalf("expected 2 merged processes, got %d", len(row.Processes))
	}
	if len(row.ExternalIPList) != 1 || row.ExternalIPList[0] != "203.0.113.10" {
		t.Fatalf("unexpected externalIpList: %+v", row.ExternalIPList)
	}
	if len(row.InternalIPList) != 1 || row.InternalIPList[0] != "10.0.0.10" {
		t.Fatalf("unexpected internalIpList: %+v", row.InternalIPList)
	}
}

func TestMergeRowsDoesNotCollapseRowsWithoutIdentity(t *testing.T) {
	rows := []SoftwareInfo{
		{Processes: []SoftwareProcess{{PID: intPtr(1), Name: strPtr("a")}}},
		{Processes: []SoftwareProcess{{PID: intPtr(2), Name: strPtr("b")}}},
	}
	merged := mergeRows(rows)
	if len(merged) != 2 {
		t.Fatalf("expected rows without merge key to stay separate, got %d", len(merged))
	}
}
