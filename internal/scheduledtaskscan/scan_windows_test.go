//go:build windows

package scheduledtaskscan

import "testing"

func TestParseWindowsXMLTaskFromUTF16(t *testing.T) {
	xmlText := "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Principals><Principal><UserId>SYSTEM</UserId></Principal></Principals><Triggers><TimeTrigger><StartBoundary>2026-03-01T10:00:00</StartBoundary></TimeTrigger></Triggers><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Command>C:\\Windows\\System32\\cmd.exe</Command><Arguments>/c test.bat</Arguments></Exec></Actions></Task>"
	encoded := []byte{0xFF, 0xFE}
	for _, r := range xmlText {
		encoded = append(encoded, byte(r), byte(r>>8))
	}
	decoded, ok := decodeTaskXML(encoded)
	if !ok {
		t.Fatalf("expected decode success")
	}
	if len(decoded) == 0 {
		t.Fatalf("expected decoded xml")
	}

	if inferWindowsTaskType("C:\\run\\job.cmd", "") != "BATCH" {
		t.Fatalf("expected BATCH type")
	}
	if inferWindowsTaskType("C:\\run\\job.exe", "C:\\Windows\\Tasks\\legacy.job") != "AT" {
		t.Fatalf("expected AT type")
	}
}
