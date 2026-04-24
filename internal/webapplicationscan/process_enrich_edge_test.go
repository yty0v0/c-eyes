package webapplicationscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"edrsystem/internal/processscan"
)

func TestExtractConfigPathFromArgsVariants(t *testing.T) {
	tests := []struct {
		name string
		kind string
		raw  string
		want string
	}{
		{
			name: "nginx short flag with quoted path",
			kind: "nginx",
			raw:  `-g "daemon off;" -c "/etc/nginx/custom.conf"`,
			want: "/etc/nginx/custom.conf",
		},
		{
			name: "apache long flag equals",
			kind: "apache",
			raw:  `--config=/etc/httpd/conf/httpd.conf`,
			want: "/etc/httpd/conf/httpd.conf",
		},
		{
			name: "tomcat config token fallback",
			kind: "tomcat",
			raw:  `/opt/tomcat/conf/server.xml`,
			want: "/opt/tomcat/conf/server.xml",
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

func TestEnrichWebApplicationsWithProcessesRelativeConfigPath(t *testing.T) {
	dir := t.TempDir()
	exeDir := filepath.Join(dir, "bin")
	confDir := filepath.Join(exeDir, "conf")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	cfg := filepath.Join(confDir, "nginx.conf")
	if err := os.WriteFile(cfg, []byte(`
server {
  server_name edge.example.com;
  root /srv/edge;
}
`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	exePath := filepath.Join(exeDir, "nginx")

	orig := listProcessRowsFn
	listProcessRowsFn = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
		_ = ctx
		return []processscan.ProcessInfo{
			{
				Name:      strPtr("nginx"),
				Path:      strPtr(exePath),
				StartArgs: strPtr(`-c conf/nginx.conf`),
			},
		}, nil
	}
	defer func() { listProcessRowsFn = orig }()

	rows := enrichWebApplicationsWithProcesses(context.Background(), nil)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].RootPath == nil || *rows[0].RootPath != cfg {
		t.Fatalf("unexpected rootPath: %+v, want %s", rows[0].RootPath, cfg)
	}
	if rows[0].DomainName == nil || *rows[0].DomainName != "edge.example.com" {
		t.Fatalf("unexpected domainName: %+v", rows[0].DomainName)
	}
}

func TestDetectWebProcessKindAndConfigIgnoresUnrelatedArgsKeyword(t *testing.T) {
	proc := processscan.ProcessInfo{
		Name:      strPtr("c-eyes"),
		Path:      strPtr("/usr/local/bin/c-eyes"),
		StartArgs: strPtr("hostscan --custom application -appName nginx"),
	}

	kind, cfg := detectWebProcessKindAndConfig(proc)
	if kind != "" || cfg != "" {
		t.Fatalf("expected no web kind for unrelated process, got kind=%q cfg=%q", kind, cfg)
	}
}

func TestDetectWebProcessKindAndConfigTomcatFromJavaMarkers(t *testing.T) {
	proc := processscan.ProcessInfo{
		Name: strPtr("java"),
		Path: strPtr("/usr/lib/jvm/java-17-openjdk/bin/java"),
		StartArgs: strPtr(
			"-Dcatalina.base=/opt/tomcat -Dcatalina.home=/opt/tomcat org.apache.catalina.startup.Bootstrap start",
		),
	}

	kind, _ := detectWebProcessKindAndConfig(proc)
	if kind != "tomcat" {
		t.Fatalf("expected tomcat kind, got %q", kind)
	}
}
