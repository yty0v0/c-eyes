package main

import (
	"encoding/json"
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/websitescan"
)

var webSiteScanExcelHeaders = []string{
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

func writeWebSiteScanExcel(path string, rows []websitescan.WebSiteInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "web-site-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range webSiteScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := webSiteScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func webSiteScanExcelRow(row websitescan.WebSiteInfo) []any {
	return []any{
		stringVal(row.DisplayIP),
		joinStrings(row.ExternalIPList),
		joinStrings(row.InternalIPList),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Hostname),
		intVal(row.PID),
		stringVal(row.Allow),
		stringVal(row.Deny),
		stringVal(row.Cmd),
		webSiteDomainsAsJSON(row.Domains),
		stringVal(row.User),
		stringVal(row.Type),
		intVal(row.Port),
		stringVal(row.Proto),
		intVal(row.PortStatus),
		boolVal(row.SecurityEnabled),
		webSiteVirtualDirAsJSON(row.VirtualDir),
		webSiteRootAsJSON(row.Root),
		intVal(row.VirtualDirCount),
		intVal(row.BindingCount),
		stringVal(row.DeployPath),
		stringVal(row.ConfigName),
		intVal(row.State),
		stringVal(row.Path),
		boolVal(row.IsRunning),
	}
}

func webSiteDomainsAsJSON(list []websitescan.DomainInfo) string {
	if len(list) == 0 {
		return "[]"
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func webSiteVirtualDirAsJSON(list []websitescan.VirtualDirInfo) string {
	if len(list) == 0 {
		return "[]"
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func webSiteRootAsJSON(root *websitescan.VirtualDirInfo) string {
	if root == nil {
		return "{}"
	}
	b, err := json.Marshal(root)
	if err != nil {
		return "{}"
	}
	return string(b)
}
