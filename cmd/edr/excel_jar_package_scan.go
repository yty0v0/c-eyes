package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/jarpackagescan"
)

var jarPackageScanExcelHeaders = []string{
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
	"executable",
	"path",
}

func writeJarPackageScanExcel(path string, rows []jarpackagescan.JarPackageRecord) error {
	if path == "" {
		return fmt.Errorf("excel output path cannot be empty")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "jar-package-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range jarPackageScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := jarPackageScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func jarPackageScanExcelRow(row jarpackagescan.JarPackageRecord) []any {
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
		intVal(row.Type),
		boolVal(row.Executable),
		stringVal(row.Path),
	}
}
