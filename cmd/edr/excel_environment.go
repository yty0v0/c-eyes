package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/environmentscan"
)

var environmentScanExcelHeaders = []string{
	"displayIp",
	"externalIpList",
	"internalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"key",
	"value",
	"user",
	"sysEnv",
}

func writeEnvironmentScanExcel(path string, rows []environmentscan.EnvironmentInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "environment-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range environmentScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := environmentScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func environmentScanExcelRow(row environmentscan.EnvironmentInfo) []any {
	return []any{
		stringVal(row.DisplayIP),
		joinStrings(row.ExternalIPList),
		joinStrings(row.InternalIPList),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Hostname),
		stringVal(row.Key),
		stringVal(row.Value),
		stringVal(row.User),
		boolVal(row.SysEnv),
	}
}
