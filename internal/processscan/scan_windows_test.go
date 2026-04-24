//go:build windows

package processscan

import "testing"

func TestFormatHex(t *testing.T) {
	if formatHex(0x0409) != "0409" {
		t.Fatalf("unexpected hex: %s", formatHex(0x0409))
	}
	if formatHex(0x04B0) != "04B0" {
		t.Fatalf("unexpected hex: %s", formatHex(0x04B0))
	}
}
