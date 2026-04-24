//go:build linux

package kernelscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcModulesLine(t *testing.T) {
	row, ok := parseProcModulesLine("nf_conntrack 196608 4 xt_conntrack,nf_nat,xt_MASQUERADE,xt_state, Live 0xffffffffc0000000")
	if !ok {
		t.Fatalf("expected parse success")
	}
	if row.ModuleName == nil || *row.ModuleName != "nf_conntrack" {
		t.Fatalf("unexpected module name: %+v", row.ModuleName)
	}
	if row.Size == nil || *row.Size != "196608" {
		t.Fatalf("unexpected size: %+v", row.Size)
	}
	if len(row.Depends) != 4 || row.Depends[0] != "xt_conntrack" {
		t.Fatalf("unexpected depends: %+v", row.Depends)
	}
}

func TestLinuxModuleKeyFromPath(t *testing.T) {
	tests := map[string]string{
		"/lib/modules/6.8.0/kernel/net/netfilter/nf_conntrack.ko":       "nf_conntrack",
		"/lib/modules/6.8.0/kernel/drivers/acpi/button.ko.xz":           "button",
		"/lib/modules/6.8.0/kernel/drivers/char/tpm/tpm_tis.ko.zst":     "tpm_tis",
		"/lib/modules/6.8.0/kernel/drivers/input/mouse/vmmouse.ko.gz":   "vmmouse",
		"/lib/modules/6.8.0/kernel/drivers/media/video/videodev.ko.bz2": "videodev",
	}
	for input, want := range tests {
		got := linuxModuleKeyFromPath(input)
		if got != want {
			t.Fatalf("unexpected key for %s: got %q want %q", input, got, want)
		}
	}
}

func TestParseLinuxDepends(t *testing.T) {
	got := parseLinuxDepends("xt_conntrack,nf_nat,xt_MASQUERADE")
	if len(got) != 3 {
		t.Fatalf("expected 3 depends entries, got %d", len(got))
	}
	if got[0] != "xt_conntrack" || got[1] != "nf_nat" || got[2] != "xt_MASQUERADE" {
		t.Fatalf("unexpected depends: %+v", got)
	}

	empty := parseLinuxDepends("-")
	if len(empty) != 0 {
		t.Fatalf("expected empty depends for '-', got %+v", empty)
	}
}

func TestParseLinuxModulesDep(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "modules")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}

	depPath := filepath.Join(root, "modules.dep")
	content := "" +
		"kernel/drivers/net/e1000e/e1000e.ko: kernel/drivers/net/ptp/ptp.ko\n" +
		"kernel/net/netfilter/nf_conntrack.ko.xz: kernel/net/netfilter/nf_nat.ko.xz\n"
	if err := os.WriteFile(depPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write modules.dep: %v", err)
	}

	got := parseLinuxModulesDep(depPath, root)
	if len(got) != 2 {
		t.Fatalf("expected 2 module mappings, got %d", len(got))
	}

	if _, ok := got["e1000e"]; !ok {
		t.Fatalf("expected e1000e mapping, got %+v", got)
	}
	if _, ok := got["nf_conntrack"]; !ok {
		t.Fatalf("expected nf_conntrack mapping, got %+v", got)
	}
}
