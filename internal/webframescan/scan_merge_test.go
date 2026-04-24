package webframescan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"edrsystem/internal/webapplicationscan"
)

func TestScanStaticDynamicMergeLinuxFixture(t *testing.T) {
	orig := scanWebApplicationsFn
	scanWebApplicationsFn = func(ctx context.Context, params webapplicationscan.WebApplicationScanParams) (webapplicationscan.WebApplicationScanResult, error) {
		_ = ctx
		_ = params
		return webapplicationscan.WebApplicationScanResult{
			Rows: []webapplicationscan.WebApplicationInfo{
				{
					Hostname:   strPtr("linux-node"),
					AppName:    strPtr("nginx"),
					ServerName: strPtr("nginx"),
					RootPath:   strPtr("/etc/nginx/nginx.conf"),
					WebRoot:    strPtr("/srv/www"),
					DomainName: strPtr("linux.example.com"),
				},
				{
					Hostname:   strPtr("linux-node"),
					AppName:    strPtr("nginx"),
					ServerName: strPtr("nginx"),
					RootPath:   strPtr("/etc/nginx/nginx.conf"),
					Version:    strPtr("1.24.0"),
				},
			},
		}, nil
	}
	defer func() { scanWebApplicationsFn = orig }()

	result, err := Scan(context.Background(), WebFrameScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected merged total=1, got %d", result.Total)
	}
	row := result.Rows[0]
	if row.Version == nil || *row.Version != "1.24.0" {
		t.Fatalf("expected merged version, got %+v", row.Version)
	}
	if row.WebRoot == nil || *row.WebRoot != "/srv/www" {
		t.Fatalf("expected merged webRoot, got %+v", row.WebRoot)
	}
}

func TestScanStaticDynamicMergeWindowsFixture(t *testing.T) {
	orig := scanWebApplicationsFn
	scanWebApplicationsFn = func(ctx context.Context, params webapplicationscan.WebApplicationScanParams) (webapplicationscan.WebApplicationScanResult, error) {
		_ = ctx
		_ = params
		return webapplicationscan.WebApplicationScanResult{
			Rows: []webapplicationscan.WebApplicationInfo{
				{
					Hostname:       strPtr("win-node"),
					AppName:        strPtr("tomcat"),
					ServerName:     strPtr("tomcat"),
					RootPath:       strPtr(`C:\Tomcat\conf\server.xml`),
					InternalIPList: []string{"10.0.0.9"},
				},
				{
					Hostname:       strPtr("win-node"),
					AppName:        strPtr("tomcat"),
					ServerName:     strPtr("tomcat"),
					RootPath:       strPtr(`C:\Tomcat\conf\server.xml`),
					Version:        strPtr("9.0.82"),
					ExternalIPList: []string{"203.0.113.8"},
				},
			},
		}, nil
	}
	defer func() { scanWebApplicationsFn = orig }()

	result, err := Scan(context.Background(), WebFrameScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected merged total=1, got %d", result.Total)
	}
	row := result.Rows[0]
	if len(row.InternalIPList) != 1 || row.InternalIPList[0] != "10.0.0.9" {
		t.Fatalf("expected merged internalIpList, got %+v", row.InternalIPList)
	}
	if len(row.ExternalIPList) != 1 || row.ExternalIPList[0] != "203.0.113.8" {
		t.Fatalf("expected merged externalIpList, got %+v", row.ExternalIPList)
	}
}

func TestScanCollectsTomcatJarListFromConfigPath(t *testing.T) {
	base := t.TempDir()
	confDir := filepath.Join(base, "conf")
	libDir := filepath.Join(base, "lib")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf: %v", err)
	}
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("mkdir lib: %v", err)
	}
	configPath := filepath.Join(confDir, "server.xml")
	if err := os.WriteFile(configPath, []byte(`<Server></Server>`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "spring-core-6.1.2.jar"), []byte("stub"), 0o644); err != nil {
		t.Fatalf("write jar: %v", err)
	}

	orig := scanWebApplicationsFn
	scanWebApplicationsFn = func(ctx context.Context, params webapplicationscan.WebApplicationScanParams) (webapplicationscan.WebApplicationScanResult, error) {
		_ = ctx
		_ = params
		return webapplicationscan.WebApplicationScanResult{
			Rows: []webapplicationscan.WebApplicationInfo{
				{
					AppName:    strPtr("tomcat"),
					ServerName: strPtr("tomcat"),
					RootPath:   &configPath,
				},
			},
		}, nil
	}
	defer func() { scanWebApplicationsFn = orig }()

	result, err := Scan(context.Background(), WebFrameScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if result.Rows[0].JarCount == nil || *result.Rows[0].JarCount != "1" {
		t.Fatalf("expected jarCount=1, got %+v", result.Rows[0].JarCount)
	}
	if len(result.Rows[0].JarList) != 1 {
		t.Fatalf("expected jarList size=1, got %d", len(result.Rows[0].JarList))
	}
	if result.Rows[0].JarList[0].JarName == nil || *result.Rows[0].JarList[0].JarName != "spring-core-6.1.2.jar" {
		t.Fatalf("unexpected jar name: %+v", result.Rows[0].JarList[0].JarName)
	}
}
