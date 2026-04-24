package main

import (
	"encoding/json"
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/webframescan"
)

var webFrameworkScanExcelHeaders = []string{
	"displayIp",
	"externalIpList",
	"internalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"name",
	"version",
	"type",
	"serverName",
	"domainName",
	"webAppDir",
	"jarCount",
	"jarList",
	"webRoot",
	"workDir",
}

func writeWebFrameworkScanExcel(path string, rows []webframescan.WebFrameRecord) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "web-framework-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range webFrameworkScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := webFrameworkScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func webFrameworkScanExcelRow(row webframescan.WebFrameRecord) []any {
	return []any{
		stringVal(row.DisplayIP),
		joinStrings(row.ExternalIPList),
		joinStrings(row.InternalIPList),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Hostname),
		stringVal(row.Name),
		stringVal(row.Version),
		stringVal(row.Type),
		stringVal(row.ServerName),
		stringVal(row.DomainName),
		stringVal(row.WebAppDir),
		stringVal(row.JarCount),
		jarListAsJSON(row.JarList),
		stringVal(row.WebRoot),
		stringVal(row.WorkDir),
	}
}

func jarListAsJSON(list []webframescan.JarRecord) string {
	if len(list) == 0 {
		return "[]"
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "[]"
	}
	return string(b)
}
