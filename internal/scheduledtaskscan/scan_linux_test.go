//go:build linux

package scheduledtaskscan

import "testing"

func TestParseCronLine(t *testing.T) {
	schedule, userName, command, ok := parseCronLine("*/5 * * * * root /usr/bin/backup", true, "")
	if !ok {
		t.Fatalf("expected parse success")
	}
	if schedule != "*/5 * * * *" {
		t.Fatalf("unexpected schedule: %s", schedule)
	}
	if userName != "root" {
		t.Fatalf("unexpected user: %s", userName)
	}
	if command != "/usr/bin/backup" {
		t.Fatalf("unexpected command: %s", command)
	}

	schedule, userName, command, ok = parseCronLine("@reboot /usr/bin/python3 /opt/app.py", false, "alice")
	if !ok {
		t.Fatalf("expected parse success")
	}
	if schedule != "@reboot" {
		t.Fatalf("unexpected schedule: %s", schedule)
	}
	if userName != "alice" {
		t.Fatalf("unexpected user: %s", userName)
	}
	if command != "/usr/bin/python3 /opt/app.py" {
		t.Fatalf("unexpected command: %s", command)
	}
}

func TestInferLinuxAtTaskType(t *testing.T) {
	if inferLinuxAtTaskType("job.batch") != "BATCH" {
		t.Fatalf("expected BATCH type")
	}
	if inferLinuxAtTaskType("a00012031") != "AT" {
		t.Fatalf("expected AT type")
	}
}
