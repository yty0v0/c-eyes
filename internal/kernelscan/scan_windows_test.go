//go:build windows

package kernelscan

import "testing"

func TestNormalizeWindowsDriverPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: `\\?\C:\Windows\System32\drivers\tcpip.sys`, want: `C:\Windows\System32\drivers\tcpip.sys`},
		{input: `\??\C:\Windows\System32\drivers\ndis.sys`, want: `C:\Windows\System32\drivers\ndis.sys`},
	}
	for _, tt := range tests {
		got := normalizeWindowsDriverPath(tt.input)
		if got != tt.want {
			t.Fatalf("unexpected normalized path: got %q want %q", got, tt.want)
		}
	}
}
