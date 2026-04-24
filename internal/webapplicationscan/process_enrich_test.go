package webapplicationscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"edrsystem/internal/processscan"
)

func TestEnrichWebApplicationsWithProcessesDiscoversConfigPath(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(cfg, []byte(`
server {
  server_name process.example.com;
  root /srv/process-app;
}
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	orig := listProcessRowsFn
	listProcessRowsFn = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
		_ = ctx
		return []processscan.ProcessInfo{
			{
				Name:      strPtr("nginx"),
				Path:      strPtr("/usr/sbin/nginx"),
				StartArgs: strPtr("-c " + cfg),
				Version:   strPtr("1.24.0"),
			},
		}, nil
	}
	defer func() { listProcessRowsFn = orig }()

	rows := enrichWebApplicationsWithProcesses(context.Background(), nil)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].ServerName == nil || *rows[0].ServerName != "nginx" {
		t.Fatalf("unexpected serverName: %+v", rows[0].ServerName)
	}
	if rows[0].RootPath == nil || *rows[0].RootPath != cfg {
		t.Fatalf("unexpected rootPath: %+v", rows[0].RootPath)
	}
	if rows[0].WebRoot == nil || *rows[0].WebRoot != "/srv/process-app" {
		t.Fatalf("unexpected webRoot: %+v", rows[0].WebRoot)
	}
	if rows[0].DomainName == nil || *rows[0].DomainName != "process.example.com" {
		t.Fatalf("unexpected domainName: %+v", rows[0].DomainName)
	}
}
