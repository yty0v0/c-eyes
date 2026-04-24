package processscan

import (
	"testing"
	"time"
)

func TestApplyFilters_NameAndPID(t *testing.T) {
	host := HostInfo{Hostname: "test-host"}
	proc1 := ProcessInfo{PID: intPtr(100), Name: strPtr("sshd")}
	proc2 := ProcessInfo{PID: intPtr(200), Name: strPtr("nginx")}

	params := ProcessScanParams{
		Name: strPtr("ssh"),
		PIDs: []int{100, 300},
	}

	filtered := ApplyFilters([]ProcessInfo{proc1, proc2}, params, host)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 process, got %d", len(filtered))
	}
	if filtered[0].PID == nil || *filtered[0].PID != 100 {
		t.Fatalf("expected pid 100")
	}
}

func TestApplyFilters_StartTime(t *testing.T) {
	host := HostInfo{Hostname: "test-host"}
	now := time.Now()
	earlier := now.Add(-2 * time.Hour)

	proc1 := ProcessInfo{PID: intPtr(1), StartTime: timePtr(now)}
	proc2 := ProcessInfo{PID: intPtr(2), StartTime: timePtr(earlier)}
	params := ProcessScanParams{StartTime: timePtr(now.Add(-time.Hour))}

	filtered := ApplyFilters([]ProcessInfo{proc1, proc2}, params, host)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 process, got %d", len(filtered))
	}
	if filtered[0].PID == nil || *filtered[0].PID != 1 {
		t.Fatalf("expected pid 1")
	}
}

func TestApplyFilters_Hostname(t *testing.T) {
	host := HostInfo{Hostname: "server-alpha"}
	params := ProcessScanParams{Hostname: strPtr("alpha")}

	filtered := ApplyFilters([]ProcessInfo{{PID: intPtr(1)}}, params, host)
	if len(filtered) != 1 {
		t.Fatalf("expected host match")
	}

	params.Hostname = strPtr("beta")
	filtered = ApplyFilters([]ProcessInfo{{PID: intPtr(1)}}, params, host)
	if len(filtered) != 0 {
		t.Fatalf("expected host mismatch")
	}
}
