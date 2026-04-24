package webapplicationscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigWithIncludes(t *testing.T) {
	dir := t.TempDir()
	confd := filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(confd, 0o755); err != nil {
		t.Fatalf("mkdir conf.d: %v", err)
	}
	mainCfg := filepath.Join(dir, "nginx.conf")
	subCfg := filepath.Join(confd, "site.conf")
	if err := os.WriteFile(mainCfg, []byte("include conf.d/*.conf;\n"), 0o644); err != nil {
		t.Fatalf("write main cfg: %v", err)
	}
	if err := os.WriteFile(subCfg, []byte("server_name include.example.com;\n"), 0o644); err != nil {
		t.Fatalf("write sub cfg: %v", err)
	}

	resolved, merged, err := loadConfigWithIncludes(mainCfg, os.ReadFile)
	if err != nil {
		t.Fatalf("loadConfigWithIncludes: %v", err)
	}
	if resolved == "" {
		t.Fatalf("expected resolved path")
	}
	if !strings.Contains(merged, "include.example.com") {
		t.Fatalf("expected merged include content, got: %s", merged)
	}
}
