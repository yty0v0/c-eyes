//go:build windows

package databasescan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectWindowsDBAvoidsOracleProviderFalsePositive(t *testing.T) {
	service := ".NET Data Provider for Oracle"
	image := `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\OraProvCfg.exe`
	if got := detectWindowsDB(service, image); got != "" {
		t.Fatalf("expected no database detection, got %q", got)
	}
}

func TestParseCommandLinePreservesQuotedDefaultsFile(t *testing.T) {
	cmd := `"D:\MySQL\MySQL Server 8.0\bin\mysqld.exe" --defaults-file="D:\MySQL\MySQL Server 8.0\my.ini" MySQL80`
	args := parseCommandLine(cmd)
	if len(args) < 2 {
		t.Fatalf("expected parsed args, got %v", args)
	}
	conf := extractArgValue(args, "--defaults-file")
	want := `D:\MySQL\MySQL Server 8.0\my.ini`
	if conf != want {
		t.Fatalf("expected defaults-file %q, got %q (args=%v)", want, conf, args)
	}
}

func TestParseMySQLPortFromConfig(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "my.ini")
	content := "[mysqld]\n# comment\nport = 3307\n"
	if err := os.WriteFile(conf, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	port := parseMySQLPortFromConfig(strPtr(conf))
	if port == nil || *port != 3307 {
		t.Fatalf("expected port 3307, got %+v", port)
	}
}
