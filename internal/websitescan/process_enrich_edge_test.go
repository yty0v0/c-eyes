package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"edrsystem/internal/processscan"
)

func TestExtractWebSiteConfigPathFromArgsVariants(t *testing.T) {
	tests := []struct {
		name string
		kind string
		raw  string
		want string
	}{
		{
			name: "nginx short flag quoted",
			kind: "nginx",
			raw:  `-c "/etc/nginx/custom.conf"`,
			want: "/etc/nginx/custom.conf",
		},
		{
			name: "apache equals style",
			kind: "apache",
			raw:  `--config=/etc/httpd/conf/httpd.conf`,
			want: "/etc/httpd/conf/httpd.conf",
		},
		{
			name: "iis config token fallback",
			kind: "iis",
			raw:  `C:\Windows\System32\inetsrv\config\applicationHost.config`,
			want: `C:\Windows\System32\inetsrv\config\applicationHost.config`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractConfigPathFromArgs(tt.kind, tt.raw)
			if got != tt.want {
				t.Fatalf("extractConfigPathFromArgs() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnrichWebSitesWithProcessesMergesExistingRow(t *testing.T) {
	rows := []WebSiteInfo{
		{
			Type:       strPtr("nginx"),
			ConfigName: strPtr("nginx.conf"),
		},
	}
	orig := listWebSiteProcessRowsFn
	listWebSiteProcessRowsFn = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
		_ = ctx
		return []processscan.ProcessInfo{
			{
				Name:      strPtr("nginx"),
				StartArgs: strPtr("-c /tmp/nginx.conf"),
				PID:       intPtr(1234),
				Uname:     strPtr("www-data"),
			},
		}, nil
	}
	defer func() { listWebSiteProcessRowsFn = orig }()

	out := enrichWebSitesWithProcesses(context.Background(), rows)
	if len(out) != 1 {
		t.Fatalf("expected merged single row, got %d", len(out))
	}
	if out[0].PID == nil || *out[0].PID != 1234 {
		t.Fatalf("unexpected pid: %+v", out[0].PID)
	}
	if out[0].User == nil || *out[0].User != "www-data" {
		t.Fatalf("unexpected user: %+v", out[0].User)
	}
}

func TestEnrichWebSitesWithProcessesRelativeConfigPath(t *testing.T) {
	dir := t.TempDir()
	exeDir := filepath.Join(dir, "bin")
	confDir := filepath.Join(exeDir, "conf")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}
	cfg := filepath.Join(confDir, "nginx.conf")
	if err := os.WriteFile(cfg, []byte(`
server {
  server_name edge-site.example.com;
  root /srv/edge-site;
  listen 9443 ssl;
}
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	exePath := filepath.Join(exeDir, "nginx")

	orig := listWebSiteProcessRowsFn
	listWebSiteProcessRowsFn = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
		_ = ctx
		return []processscan.ProcessInfo{
			{
				Name:      strPtr("nginx"),
				Path:      strPtr(exePath),
				StartArgs: strPtr(`-c conf/nginx.conf`),
				PID:       intPtr(4567),
			},
		}, nil
	}
	defer func() { listWebSiteProcessRowsFn = orig }()

	out := enrichWebSitesWithProcesses(context.Background(), nil)
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	row := out[0]
	if row.Port == nil || *row.Port != 9443 {
		t.Fatalf("unexpected port: %+v", row.Port)
	}
	if row.Proto == nil || *row.Proto != "https" {
		t.Fatalf("unexpected proto: %+v", row.Proto)
	}
	if row.PID == nil || *row.PID != 4567 {
		t.Fatalf("unexpected pid: %+v", row.PID)
	}
	if row.ConfigName == nil || *row.ConfigName != "nginx.conf" {
		t.Fatalf("unexpected configName: %+v", row.ConfigName)
	}
}
