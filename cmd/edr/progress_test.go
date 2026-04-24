package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestTerminalProgressUpdateAndDone(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgress(&out, "risk analyze")
	progress.Update(1, 4, "fast_lookup")
	progress.Done()

	got := out.String()
	if !strings.Contains(got, "risk analyze [") {
		t.Fatalf("expected progress label in output, got %q", got)
	}
	if !strings.Contains(got, "25% (1/4)") {
		t.Fatalf("expected progress percentage and counters, got %q", got)
	}
	if !strings.Contains(got, "fast_lookup") {
		t.Fatalf("expected stage in output, got %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("expected trailing newline after Done, got %q", got)
	}
}

func TestTerminalProgressIgnoresInvalidTotal(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgress(&out, "risk analyze")
	progress.Update(1, 0, "ignored")
	progress.Done()

	if got := out.String(); got != "" {
		t.Fatalf("expected no output for invalid total, got %q", got)
	}
}

func TestTerminalProgressPrintLineSeparatesProgressRow(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgress(&out, "risk analyze")
	progress.Update(1, 1, "cloud_only")
	progress.PrintLine("risk analyze: auto budget finalized: mode=cloud_only N=1 U=0 C=2 total=2m0s")
	progress.Done()

	got := out.String()
	if strings.Contains(got, "cloud_onlyrisk analyze:") {
		t.Fatalf("expected diagnostic line to be separated from progress row, got %q", got)
	}
	if !strings.Contains(got, "\nrisk analyze: auto budget finalized") && !strings.Contains(got, "\rrisk analyze: auto budget finalized") {
		t.Fatalf("expected diagnostic line to be emitted as a standalone row, got %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("expected output to end with newline, got %q", got)
	}
}

func TestTerminalProgressPinnedKeepsProgressAtTop(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgressWithPin(&out, "hostscan", true)
	progress.Update(1, 2, "account | complete")
	progress.PrintLine("hostscan failed | module=startup | reason=Access is denied.")
	progress.Update(2, 2, "port | complete")
	progress.Done()

	got := out.String()
	if !strings.Contains(got, "hostscan failed | module=startup | reason=Access is denied.") {
		t.Fatalf("expected error line in output, got %q", got)
	}
	if !strings.Contains(got, "\x1b[?25l") {
		t.Fatalf("expected cursor-hide sequence in pinned mode, got %q", got)
	}
	if !strings.Contains(got, "\x1b[?25h") {
		t.Fatalf("expected cursor-show sequence on Done in pinned mode, got %q", got)
	}
	if !strings.Contains(got, "\x1b[2A") || !strings.Contains(got, "\x1b[2B\r") {
		t.Fatalf("expected cursor up/down sequences for pinned progress, got %q", got)
	}
	if !strings.Contains(got, "100% (2/2)") {
		t.Fatalf("expected final pinned progress update, got %q", got)
	}
}

func TestTerminalProgressPinnedLogBeforeFirstUpdateKeepsTopRowForProgress(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgressWithPin(&out, "hostscan", true)
	progress.PrintLine("[WARN] hostscan module startup failed: Access is denied.")
	progress.Update(1, 1, "process | complete")
	progress.Done()

	got := out.String()
	if !strings.Contains(got, "\n[WARN] hostscan module startup failed: Access is denied.\n") {
		t.Fatalf("expected warning line output with reserved top row, got %q", got)
	}
	if !strings.Contains(got, "\x1b[2A") || !strings.Contains(got, "\x1b[2B\r") {
		t.Fatalf("expected cursor up/down sequences for top-pinned progress redraw, got %q", got)
	}
	if !strings.Contains(got, "100% (1/1)") {
		t.Fatalf("expected final progress content, got %q", got)
	}
}

func TestScopedProgressUpdatePrefixesScopeAndStage(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgress(&out, "hostscan")
	update := scopedProgressUpdate(progress, "account")
	update(2, 5, "collect")
	progress.Done()

	got := out.String()
	if !strings.Contains(got, "hostscan [") {
		t.Fatalf("expected progress label, got %q", got)
	}
	if !strings.Contains(got, "40% (2/5)") {
		t.Fatalf("expected progress counters, got %q", got)
	}
	if !strings.Contains(got, "account | collect") {
		t.Fatalf("expected scoped stage text, got %q", got)
	}
}

func TestScopedProgressUpdateUsesScopeWhenStageEmpty(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgress(&out, "filescan")
	update := scopedProgressUpdate(progress, "jarpackage")
	update(1, 2, "")
	progress.Done()

	got := out.String()
	if !strings.Contains(got, "jarpackage") {
		t.Fatalf("expected scope as stage fallback, got %q", got)
	}
}

func TestIsPinnedProgressEnabledEnvOverride(t *testing.T) {
	t.Setenv("CEYES_PROGRESS_PINNED", "1")
	if !isPinnedProgressEnabled() {
		t.Fatal("expected pinned progress to be enabled by env override")
	}

	t.Setenv("CEYES_PROGRESS_PINNED", "0")
	if isPinnedProgressEnabled() {
		t.Fatal("expected pinned progress to be disabled by env override")
	}
}

func TestIsPinnedProgressEnabledDefaultPolicy(t *testing.T) {
	t.Setenv("CEYES_PROGRESS_PINNED", "")
	want := runtime.GOOS != "windows"
	if got := isPinnedProgressEnabled(); got != want {
		t.Fatalf("unexpected default pinned policy: got=%v want=%v", got, want)
	}
}
