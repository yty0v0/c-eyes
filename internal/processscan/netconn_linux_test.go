//go:build linux

package processscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcNetRemoteFileFiltersExternalPeers(t *testing.T) {
	content := "" +
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 08080808:0050 01 00000000:00000000 00:00000000 00000000   100        0 12345 1 0000000000000000 100 0 0 10 -1\n" +
		"   1: 0100007F:1F90 0100000A:0050 01 00000000:00000000 00:00000000 00000000   100        0 23456 1 0000000000000000 100 0 0 10 -1\n" +
		"   2: 00000000:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 34567 1 0000000000000000 100 0 0 10 -1\n"

	path := filepath.Join(t.TempDir(), "tcp.fixture")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture failed: %v", err)
	}

	rows, err := parseProcNetRemoteFile(path, true)
	if err != nil {
		t.Fatalf("parseProcNetRemoteFile returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 external row, got %d", len(rows))
	}
	if rows[0].Inode != "12345" {
		t.Fatalf("unexpected inode: %q", rows[0].Inode)
	}
	if rows[0].RemoteIP != "8.8.8.8" {
		t.Fatalf("unexpected remote ip: %q", rows[0].RemoteIP)
	}
}
