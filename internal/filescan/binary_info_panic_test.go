package filescan

import (
	"strings"
	"testing"
)

func TestSafePEImportedSymbolsHandlesNil(t *testing.T) {
	t.Parallel()

	syms, err := safePEImportedSymbols(nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(syms) != 0 {
		t.Fatalf("expected empty symbols, got %#v", syms)
	}
}

func TestSafePEImportedLibrariesHandlesNil(t *testing.T) {
	t.Parallel()

	libs, err := safePEImportedLibraries(nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(libs) != 0 {
		t.Fatalf("expected empty libraries, got %#v", libs)
	}
}

func TestSafeCallStringListPassThrough(t *testing.T) {
	t.Parallel()

	got, err := safeCallStringList("test", func() ([]string, error) {
		return []string{"a", "b"}, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestSafeCallStringListRecoversPanic(t *testing.T) {
	t.Parallel()

	got, err := safeCallStringList("test symbols", func() ([]string, error) {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected panic-converted error")
	}
	if got != nil {
		t.Fatalf("expected nil result on panic, got %#v", got)
	}
	if !strings.Contains(err.Error(), "test symbols") || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("expected panic in message, got %v", err)
	}
}
