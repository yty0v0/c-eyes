//go:build linux

package startupscan

import "testing"

func TestParseRunlevelEntryName(t *testing.T) {
	name, enabled, ok := parseRunlevelEntryName("S20sshd")
	if !ok {
		t.Fatalf("expected parse success")
	}
	if name != "sshd" {
		t.Fatalf("unexpected name: %s", name)
	}
	if !enabled {
		t.Fatalf("expected enabled=true")
	}

	name, enabled, ok = parseRunlevelEntryName("K01cups")
	if !ok {
		t.Fatalf("expected parse success")
	}
	if name != "cups" {
		t.Fatalf("unexpected name: %s", name)
	}
	if enabled {
		t.Fatalf("expected enabled=false")
	}

	if _, _, ok := parseRunlevelEntryName("README"); ok {
		t.Fatalf("expected non runlevel entry to be rejected")
	}
}

func TestParseInitDefaultFromInittab(t *testing.T) {
	data := []byte(`
# comment
id:5:initdefault:
`)
	level, ok := parseInitDefaultFromInittab(data)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if level != 5 {
		t.Fatalf("unexpected level: %d", level)
	}
}

func TestParseXinetdEnabled(t *testing.T) {
	enabled := parseXinetdEnabled([]byte(`
service telnet
{
	disable = yes
}
`))
	if enabled {
		t.Fatalf("expected disabled service to return enabled=false")
	}

	enabled = parseXinetdEnabled([]byte(`
service rsync
{
	disable = no
}
`))
	if !enabled {
		t.Fatalf("expected enabled service to return enabled=true")
	}
}

func TestInferInitLevel(t *testing.T) {
	levels := [8]int{0, 0, 0, 1, 0, 0, 0, 0}
	level := inferInitLevel(5, levels, true)
	if level != 3 {
		t.Fatalf("unexpected inferred level: %d", level)
	}

	level = inferInitLevel(5, [8]int{}, true)
	if level != 5 {
		t.Fatalf("expected fallback to default level, got %d", level)
	}

	level = inferInitLevel(3, [8]int{}, false)
	if level != -1 {
		t.Fatalf("expected -1 when runlevel data missing, got %d", level)
	}
}
