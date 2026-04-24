package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"edrsystem/internal/processscan"
)

func TestEnrichWebSitesWithProcessesDiscoversConfigAndRuntimeMeta(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(cfg, []byte(`
server {
  server_name runtime.example.com;
  root /srv/runtime-app;
  listen 8443 ssl;
}
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	orig := listWebSiteProcessRowsFn
	listWebSiteProcessRowsFn = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
		_ = ctx
		return []processscan.ProcessInfo{
			{
				Name:      strPtr("nginx"),
				Path:      strPtr("/usr/sbin/nginx"),
				StartArgs: strPtr("-c " + cfg),
				PID:       intPtr(9527),
				Uname:     strPtr("www-data"),
			},
		}, nil
	}
	defer func() { listWebSiteProcessRowsFn = orig }()

	rows := enrichWebSitesWithProcesses(context.Background(), nil)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.Type == nil || *row.Type != "nginx" {
		t.Fatalf("unexpected type: %+v", row.Type)
	}
	if row.PID == nil || *row.PID != 9527 {
		t.Fatalf("unexpected pid: %+v", row.PID)
	}
	if row.User == nil || *row.User != "www-data" {
		t.Fatalf("unexpected user: %+v", row.User)
	}
	if row.Port == nil || *row.Port != 8443 {
		t.Fatalf("unexpected port: %+v", row.Port)
	}
	if row.Proto == nil || *row.Proto != "https" {
		t.Fatalf("unexpected proto: %+v", row.Proto)
	}
	if row.BindingCount == nil || *row.BindingCount != 1 {
		t.Fatalf("unexpected bindingCount: %+v", row.BindingCount)
	}
}
