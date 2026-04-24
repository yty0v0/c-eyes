package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/kernelscan"
)

var kernelScanExcelHeaders = []string{
	"displayIp",
	"externalIps",
	"internalIps",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"moduleName",
	"description",
	"path",
	"version",
	"size",
	"depends",
	"holders",
}

func writeKernelScanExcel(path string, rows []kernelscan.KernelModuleInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "kernel-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range kernelScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := kernelScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func kernelScanExcelRow(row kernelscan.KernelModuleInfo) []any {
	return []any{
		stringVal(row.DisplayIP),
		joinStrings(row.ExternalIPs),
		joinStrings(row.InternalIPs),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Hostname),
		stringVal(row.ModuleName),
		stringVal(row.Description),
		stringVal(row.Path),
		stringVal(row.Version),
		stringVal(row.Size),
		joinStrings(row.Depends),
		joinStrings(row.Holders),
	}
}
