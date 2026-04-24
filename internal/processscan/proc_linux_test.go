//go:build linux

package processscan

import "testing"

func TestParseProcStat(t *testing.T) {
	data := "1234 (bash) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 200 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	stat, err := parseProcStat(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stat.Comm != "bash" {
		t.Fatalf("expected comm bash, got %s", stat.Comm)
	}
	if stat.PPID != 1 {
		t.Fatalf("expected ppid 1, got %d", stat.PPID)
	}
	if stat.StartTicks != 200 {
		t.Fatalf("expected start ticks 200, got %d", stat.StartTicks)
	}
}

func TestParseCmdline(t *testing.T) {
	cmd := parseCmdline([]byte("/usr/bin/bash\x00-c\x00echo\x00hello\x00"))
	if cmd != "/usr/bin/bash -c echo hello" {
		t.Fatalf("unexpected cmdline: %s", cmd)
	}
}
