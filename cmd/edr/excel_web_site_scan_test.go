package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/websitescan"
)

func TestWriteWebSiteScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-site-scan.xlsx")
	rows := []websitescan.WebSiteInfo{
		{
			Type: testWebSiteStrPtr("nginx"),
			Port: testWebSiteIntPtr(443),
			Domains: []websitescan.DomainInfo{
				{Name: testWebSiteStrPtr("example.com")},
			},
		},
	}
	if err := writeWebSiteScanExcel(path, rows); err != nil {
		t.Fatalf("writeWebSiteScanExcel error: %v", err)
	}
}

func testWebSiteStrPtr(v string) *string {
	return &v
}

func testWebSiteIntPtr(v int) *int {
	return &v
}

func TestWebSiteExcelHeadersMatchJSONKeys(t *testing.T) {
	expected := []string{
		"displayIp",
		"externalIpList",
		"internalIpList",
		"bizGroupId",
		"bizGroup",
		"remark",
		"hostTagList",
		"hostname",
		"pid",
		"allow",
		"deny",
		"cmd",
		"domains",
		"user",
		"type",
		"port",
		"proto",
		"portStatus",
		"securityEnabled",
		"virtualDir",
		"root",
		"virtualDirCount",
		"bindingCount",
		"deployPath",
		"configName",
		"state",
		"path",
		"isRunning",
	}
	if len(webSiteScanExcelHeaders) != len(expected) {
		t.Fatalf("unexpected header count: got %d want %d", len(webSiteScanExcelHeaders), len(expected))
	}
	for i, key := range expected {
		if webSiteScanExcelHeaders[i] != key {
			t.Fatalf("header mismatch at %d: got %s want %s", i, webSiteScanExcelHeaders[i], key)
		}
	}
}
