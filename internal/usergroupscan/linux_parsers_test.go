package usergroupscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGroupFile(t *testing.T) {
	data := mustReadFixture(t, "group.fixture")
	entries := parseGroupFile(data)
	if len(entries) != 3 {
		t.Fatalf("expected 3 valid group entries, got %d", len(entries))
	}

	if entries[0].Name != "root" || entries[0].GID != 0 {
		t.Fatalf("unexpected root entry: %+v", entries[0])
	}
	if len(entries[0].Members) != 0 {
		t.Fatalf("expected root members empty, got %+v", entries[0].Members)
	}

	if entries[1].Name != "developers" || entries[1].GID != 1000 {
		t.Fatalf("unexpected developers entry: %+v", entries[1])
	}
	if len(entries[1].Members) != 2 || entries[1].Members[0] != "alice" || entries[1].Members[1] != "bob" {
		t.Fatalf("unexpected developers members: %+v", entries[1].Members)
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
