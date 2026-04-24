package main

import (
	"encoding/json"
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/webapplicationscan"
)

var webApplicationScanExcelHeaders = []string{
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

func writeWebApplicationScanExcel(path string, rows []webapplicationscan.WebApplicationInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "web-application-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range webApplicationScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := webApplicationScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func webApplicationScanExcelRow(row webapplicationscan.WebApplicationInfo) []any {
	return []any{
		stringVal(row.DisplayIP),
		joinStrings(row.ExternalIPList),
		joinStrings(row.InternalIPList),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Hostname),
		stringVal(row.Version),
		stringVal(row.WebRoot),
		stringVal(row.ServerName),
		stringVal(row.DomainName),
		intVal(row.PluginCount),
		stringVal(row.AppName),
		stringVal(row.Description),
		stringVal(row.RootPath),
		pluginsAsJSON(row.Plugins),
		boolVal(row.IsRunning),
	}
}

func pluginsAsJSON(list []webapplicationscan.PluginInfo) string {
	if len(list) == 0 {
		return "[]"
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "[]"
	}
	return string(b)
}
