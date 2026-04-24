package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/webapplicationscan"
)

func TestWriteWebApplicationScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-application-scan.xlsx")
	rows := []webapplicationscan.WebApplicationInfo{
		{
			AppName:     testWebAppStrPtr("nginx"),
			ServerName:  testWebAppStrPtr("nginx"),
			WebRoot:     testWebAppStrPtr("/var/www/html"),
			PluginCount: testWebAppIntPtr(1),
			Plugins: []webapplicationscan.PluginInfo{
				{PluginName: testWebAppStrPtr("ngx_http_geoip_module.so")},
			},
		},
	}
	if err := writeWebApplicationScanExcel(path, rows); err != nil {
		t.Fatalf("writeWebApplicationScanExcel error: %v", err)
	}
}

func TestWebApplicationExcelHeadersMatchJSONKeys(t *testing.T) {
	expected := []string{
		"displayIp",
		"externalIpList",
		"internalIpList",
		"bizGroupId",
		"bizGroup",
		"remark",
		"hostTagList",
		"hostname",
		"version",
		"webRoot",
		"serverName",
		"domainName",
		"pluginCount",
		"appName",
		"description",
		"rootPath",
		"plugins",
		"isRunning",
	}
	if len(webApplicationScanExcelHeaders) != len(expected) {
		t.Fatalf("unexpected header count: got %d want %d", len(webApplicationScanExcelHeaders), len(expected))
	}
	for i, key := range expected {
		if webApplicationScanExcelHeaders[i] != key {
			t.Fatalf("header mismatch at %d: got %s want %s", i, webApplicationScanExcelHeaders[i], key)
		}
	}
}

func testWebAppStrPtr(v string) *string {
	return &v
}

func testWebAppIntPtr(v int) *int {
	return &v
}
