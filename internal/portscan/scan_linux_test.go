//go:build linux

package portscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcNetTCPFiltersListenRows(t *testing.T) {
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  100 0 12345
   1: 0100007F:1770 00000000:0000 01 00000000:00000000 00:00000000 00000000  100 0 67890
`
	path := filepath.Join(t.TempDir(), "tcp.fixture")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	rows, err := parseProcNetTCP(path, "tcp")
	if err != nil {
		t.Fatalf("parseProcNetTCP error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 LISTEN row, got %d", len(rows))
	}
	if rows[0].Port != 8080 || rows[0].BindIP != "127.0.0.1" || rows[0].Inode != "12345" {
		t.Fatalf("unexpected row: %+v", rows[0])
	}
}

func TestParseProcHexIP(t *testing.T) {
	ipv4, err := parseProcHexIP("0100007F")
	if err != nil {
		t.Fatalf("parse ipv4: %v", err)
	}
	if ipv4 != "127.0.0.1" {
		t.Fatalf("unexpected ipv4: %s", ipv4)
	}

	ipv6, err := parseProcHexIP("00000000000000000000000000000000")
	if err != nil {
		t.Fatalf("parse ipv6: %v", err)
	}
	if ipv6 != "::" {
		t.Fatalf("unexpected ipv6: %s", ipv6)
	}
}

func TestParseSocketInode(t *testing.T) {
	inode, ok := parseSocketInode("socket:[98765]")
	if !ok || inode != "98765" {
		t.Fatalf("unexpected parse result: inode=%s ok=%v", inode, ok)
	}
	if _, ok := parseSocketInode("anon_inode:[eventfd]"); ok {
		t.Fatalf("expected non-socket target to be rejected")
	}
}
