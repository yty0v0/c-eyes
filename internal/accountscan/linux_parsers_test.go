package accountscan

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePasswd(t *testing.T) {
	data := mustReadFixture(t, "passwd.fixture")
	entries := parsePasswd(data)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[2].Name != "alice" {
		t.Fatalf("expected alice, got %q", entries[2].Name)
	}
	if entries[2].UID != 1000 || entries[2].GID != 1000 {
		t.Fatalf("unexpected uid/gid: %d/%d", entries[2].UID, entries[2].GID)
	}
}

func TestParseGroupMembership(t *testing.T) {
	data := mustReadFixture(t, "group.fixture")
	userGroups, gidNames := parseGroupMembership(data)
	if !stringInSlice("developers", userGroups["alice"]) {
		t.Fatalf("expected alice in developers group")
	}
	if gidNames[1000] != "alice" {
		t.Fatalf("expected gid 1000 -> alice, got %q", gidNames[1000])
	}
}

func TestParseShadow(t *testing.T) {
	data := mustReadFixture(t, "shadow.fixture")
	now := time.Date(2026, 3, 25, 0, 0, 0, 0, time.UTC)
	shadow := parseShadow(data, now)
	if len(shadow) != 3 {
		t.Fatalf("expected 3 shadow entries, got %d", len(shadow))
	}
	if !shadow["daemon"].Disabled {
		t.Fatalf("expected daemon to be disabled")
	}
	alice := shadow["alice"]
	if alice.PwdMaxDays == nil || *alice.PwdMaxDays != 30 {
		t.Fatalf("expected alice max days = 30")
	}
	if alice.PasswordInactiveDays == nil || *alice.PasswordInactiveDays != 10 {
		t.Fatalf("expected alice inactive days = 10")
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	data := mustReadFixture(t, "authorized_keys.fixture")
	keys := parseAuthorizedKeys(data, 16)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].EncryptType == nil || *keys[0].EncryptType != "ssh-rsa" {
		t.Fatalf("unexpected first key type")
	}
	if keys[0].MD5 == nil || *keys[0].MD5 == "" {
		t.Fatalf("expected md5 to be populated")
	}
}

func TestParseSudoersAndResolveSudo(t *testing.T) {
	data := mustReadFixture(t, "sudoers.fixture")
	rules := parseSudoers(data)
	if len(rules) < 2 {
		t.Fatalf("expected parsed sudo rules")
	}
	allowed, accesses := resolveSudo("alice", []string{"sudo"}, rules)
	if !allowed {
		t.Fatalf("expected alice to have sudo")
	}
	if len(accesses) == 0 {
		t.Fatalf("expected non-empty accesses")
	}
}

func TestParseLastlogRecord(t *testing.T) {
	buf := make([]byte, 296)
	now := time.Now().Unix()
	binary.LittleEndian.PutUint64(buf[:8], uint64(now))
	copy(buf[8:], []byte("pts/0"))
	copy(buf[40:], []byte("10.0.0.8"))

	entry := parseLastlogRecord(buf)
	if entry.Time == nil {
		t.Fatalf("expected login time")
	}
	if entry.TTY == nil || *entry.TTY != "pts/0" {
		t.Fatalf("unexpected tty: %+v", entry.TTY)
	}
	if entry.IP == nil || *entry.IP != "10.0.0.8" {
		t.Fatalf("unexpected ip: %+v", entry.IP)
	}
}

func mustReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}
