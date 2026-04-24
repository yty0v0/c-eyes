package scheduledtaskscan

import (
	"testing"
	"time"

	"edrsystem/internal/processscan"
)

func TestApplyFiltersTableDriven(t *testing.T) {
	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	later := now.Add(2 * time.Hour)
	rows := []ScheduledTaskInfo{
		{
			User:      strPtr("root"),
			ExecPath:  strPtr("/usr/bin/backup.sh"),
			Conf:      strPtr("/etc/crontab"),
			TaskTime:  &now,
			TaskType:  strPtr("CRONTAB"),
			CrondOpen: boolPtr(true),
		},
		{
			User:      strPtr("SYSTEM"),
			ExecPath:  strPtr("C:\\Windows\\System32\\cmd.exe"),
			Conf:      strPtr("C:\\Windows\\System32\\Tasks\\Sample"),
			TaskTime:  &later,
			TaskType:  strPtr("AT"),
			CrondOpen: boolPtr(false),
		},
	}

	host := processscan.HostInfo{
		Hostname:    "node-alpha",
		InternalIPs: []string{"192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	tests := []struct {
		name   string
		params ScheduledTaskScanParams
		want   int
	}{
		{
			name: "match user array",
			params: ScheduledTaskScanParams{
				User: []string{"root", "nobody"},
			},
			want: 1,
		},
		{
			name: "match exec path fuzzy",
			params: ScheduledTaskScanParams{
				ExecPath: strPtr("backup"),
			},
			want: 1,
		},
		{
			name: "match task type",
			params: ScheduledTaskScanParams{
				TaskType: []string{"at"},
			},
			want: 1,
		},
		{
			name: "match date range",
			params: ScheduledTaskScanParams{
				TaskTime: &DateRange{From: &now, To: &now},
			},
			want: 1,
		},
		{
			name: "match host filters",
			params: ScheduledTaskScanParams{
				Hostname: strPtr("alpha"),
				IP:       strPtr("192.168"),
				Groups:   []int64{39},
			},
			want: 2,
		},
		{
			name: "biz group mismatch",
			params: ScheduledTaskScanParams{
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

func TestIsValidTaskType(t *testing.T) {
	if !isValidTaskType("crontab") {
		t.Fatalf("expected CRONTAB to be valid")
	}
	if isValidTaskType("systemd") {
		t.Fatalf("expected systemd to be invalid")
	}
}
