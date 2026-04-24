//go:build windows

package filescan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsSignatureFields(t *testing.T) {
	path := pickWindowsCandidate(t, func(path string) bool {
		info := signatureInfo(path)
		if info == nil || info.IsSigned == nil || !*info.IsSigned {
			return false
		}
		if info.SignatureValid == nil {
			return false
		}
		if info.SignerSubject == nil || *info.SignerSubject == "" {
			return false
		}
		if info.CertificateThumbprint == nil || len(*info.CertificateThumbprint) != 40 {
			return false
		}
		return true
	})

	info := signatureInfo(path)
	if info == nil || info.IsSigned == nil || !*info.IsSigned {
		t.Fatalf("expected signed file: %s", path)
	}
	if info.SignatureValid == nil {
		t.Fatalf("expected signature_valid field")
	}
	if info.SignerSubject == nil || *info.SignerSubject == "" {
		t.Fatalf("expected signer_subject")
	}
	if info.CertificateThumbprint == nil || len(*info.CertificateThumbprint) != 40 {
		t.Fatalf("expected certificate thumbprint")
	}
}

func TestWindowsBinaryInfoPE(t *testing.T) {
	path := pickWindowsCandidate(t, func(path string) bool {
		info := binaryInfo(path)
		if info == nil || info.MagicBytes == nil {
			return false
		}
		if *info.MagicBytes != "4D 5A" {
			return false
		}
		if len(info.SectionsInfo) == 0 {
			return false
		}
		if len(info.ImportedLibraries) == 0 {
			return false
		}
		return true
	})

	info := binaryInfo(path)
	if info == nil || info.MagicBytes == nil || *info.MagicBytes != "4D 5A" {
		t.Fatalf("expected PE magic for %s", path)
	}
	if len(info.SectionsInfo) == 0 {
		t.Fatalf("expected section info for %s", path)
	}
	if len(info.ImportedLibraries) == 0 {
		t.Fatalf("expected imported libraries for %s", path)
	}
}

func TestWindowsImphash(t *testing.T) {
	path := pickWindowsCandidate(t, func(path string) bool {
		hash := imphashForFile(path)
		return hash != nil && len(*hash) == 32
	})

	hash := imphashForFile(path)
	if hash == nil || len(*hash) != 32 {
		t.Fatalf("expected imphash for %s", path)
	}
}

func TestWindowsVersionInfo(t *testing.T) {
	path := pickWindowsCandidate(t, func(path string) bool {
		info := peVersionInfo(path)
		if info == nil {
			return false
		}
		if (info.OriginalFilename == nil || *info.OriginalFilename == "") &&
			(info.FileDescription == nil || *info.FileDescription == "") {
			return false
		}
		return true
	})

	info := peVersionInfo(path)
	if info == nil {
		t.Fatalf("expected version_info for %s", path)
	}
}

func pickWindowsCandidate(t *testing.T, accept func(path string) bool) string {
	t.Helper()
	for _, path := range windowsCandidates() {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if accept == nil || accept(path) {
			return path
		}
	}
	t.Skip("no suitable Windows binary found for test")
	return ""
}

func windowsCandidates() []string {
	root := os.Getenv("WINDIR")
	if root == "" {
		root = `C:\Windows`
	}
	system32 := filepath.Join(root, "System32")
	powershell := filepath.Join(system32, "WindowsPowerShell", "v1.0", "powershell.exe")
	return []string{
		filepath.Join(system32, "notepad.exe"),
		filepath.Join(system32, "cmd.exe"),
		filepath.Join(system32, "calc.exe"),
		filepath.Join(system32, "explorer.exe"),
		filepath.Join(system32, "kernel32.dll"),
		filepath.Join(system32, "user32.dll"),
		powershell,
		strings.TrimSpace(powershell),
	}
}
