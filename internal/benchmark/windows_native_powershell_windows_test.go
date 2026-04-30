//go:build windows

package benchmark

import (
	"strings"
	"testing"
)

func TestDecodeWindowsJSONArray(t *testing.T) {
	t.Parallel()

	type sample struct {
		Name string `json:"Name"`
	}

	arrayPayload := []byte(`[{"Name":"alpha"},{"Name":"beta"}]`)
	rows, err := decodeWindowsJSONArray[sample](arrayPayload)
	if err != nil {
		t.Fatalf("decodeWindowsJSONArray array returned error: %v", err)
	}
	if len(rows) != 2 || rows[0].Name != "alpha" || rows[1].Name != "beta" {
		t.Fatalf("unexpected array decode result: %#v", rows)
	}

	objectPayload := []byte(`{"Name":"solo"}`)
	rows, err = decodeWindowsJSONArray[sample](objectPayload)
	if err != nil {
		t.Fatalf("decodeWindowsJSONArray object returned error: %v", err)
	}
	if len(rows) != 1 || rows[0].Name != "solo" {
		t.Fatalf("unexpected object decode result: %#v", rows)
	}

	nullPayload := []byte(`null`)
	rows, err = decodeWindowsJSONArray[sample](nullPayload)
	if err != nil {
		t.Fatalf("decodeWindowsJSONArray null returned error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected empty result for null payload, got %#v", rows)
	}
}

func TestSummarizeWindowsAntivirusIncludesSecurityCenterProducts(t *testing.T) {
	t.Parallel()

	summary := summarizeWindowsAntivirus(windowsAntivirusInfo{
		Detected:               true,
		SecurityCenterProducts: []string{"Windows Defender"},
		ServiceIndicators:      []string{"WinDefend"},
	})
	if summary == "" || summary == "No antivirus indicator detected" {
		t.Fatalf("expected populated antivirus summary, got %q", summary)
	}
	if want := "Windows Defender"; !strings.Contains(summary, want) {
		t.Fatalf("expected summary to contain %q, got %q", want, summary)
	}
}
