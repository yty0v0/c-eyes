package benchmark

import (
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestNativeProfileCheckCounts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		template Template
		want     int
	}{
		{template: TemplateWindows, want: 12},
		{template: TemplateLinux, want: 22},
		{template: TemplateEulerOS, want: 15},
		{template: TemplateKylin, want: 15},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.template), func(t *testing.T) {
			t.Parallel()

			profile, err := nativeProfileForTemplate(tc.template)
			if err != nil {
				t.Fatalf("nativeProfileForTemplate returned error: %v", err)
			}
			if got := len(profile.checks); got != tc.want {
				t.Fatalf("expected %d checks, got %d", tc.want, got)
			}
			if profile.uuid == "" || profile.templateTime == "" {
				t.Fatalf("expected uuid and templateTime to be non-empty, got uuid=%q templateTime=%q", profile.uuid, profile.templateTime)
			}
		})
	}
}

func TestNativeWindowsProfileHasExpectedCoreIDs(t *testing.T) {
	t.Parallel()

	profile, err := nativeProfileForTemplate(TemplateWindows)
	if err != nil {
		t.Fatalf("nativeProfileForTemplate returned error: %v", err)
	}

	wantIDs := map[string]struct{}{
		"0":  {},
		"1":  {},
		"2":  {},
		"3":  {},
		"4":  {},
		"5":  {},
		"6":  {},
		"7":  {},
		"8":  {},
		"9":  {},
		"10": {},
		"12": {},
	}

	gotIDs := make(map[string]struct{}, len(profile.checks))
	for _, check := range profile.checks {
		gotIDs[check.id] = struct{}{}
	}
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("expected %d unique ids, got %d", len(wantIDs), len(gotIDs))
	}
	for id := range wantIDs {
		if _, ok := gotIDs[id]; !ok {
			t.Fatalf("missing expected windows check id: %s", id)
		}
	}
}

func TestKeepFirstNonEmptyLines(t *testing.T) {
	t.Parallel()

	in := "\nline1\n\nline2\nline3\n"
	got := keepFirstNonEmptyLines(in, 2)
	if got != "line1\nline2" {
		t.Fatalf("expected first two non-empty lines, got %q", got)
	}
}

func TestNormalizeCommandOutputGBKOnWindows(t *testing.T) {
	t.Parallel()

	src := "管理员账户"
	encoded, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(src))
	if err != nil {
		t.Fatalf("encode GBK: %v", err)
	}

	got := normalizeCommandOutput(TemplateWindows, encoded)
	if got != src {
		t.Fatalf("expected %q, got %q", src, got)
	}
}

func TestNormalizeCommandOutputUTF16LEWithBOM(t *testing.T) {
	t.Parallel()

	// BOM + 'A' + '中' in UTF-16LE bytes.
	input := []byte{0xFF, 0xFE, 0x41, 0x00, 0x2D, 0x4E}
	got := normalizeCommandOutput(TemplateWindows, input)
	if got != "A中" {
		t.Fatalf("expected %q, got %q", "A中", got)
	}
}
