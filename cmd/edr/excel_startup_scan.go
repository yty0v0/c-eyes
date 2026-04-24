package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/startupscan"
)

var startupScanExcelHeaders = []string{
	"displayIp",
	"externalIpList",
	"internalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"name",
	"defaultOpen",
	"rc0",
	"rc1",
	"rc2",
	"rc3",
	"rc4",
	"rc5",
	"rc6",
	"rc7",
	"initLevel",
	"xinetd",
	"user",
	"enable",
	"startType",
	"publisher",
	"showName",
}

func writeStartupScanExcel(path string, rows []startupscan.StartupInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "startup-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range startupScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := startupScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func startupScanExcelRow(row startupscan.StartupInfo) []any {
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
		boolVal(row.DefaultOpen),
		intVal(row.RC0),
		intVal(row.RC1),
		intVal(row.RC2),
		intVal(row.RC3),
		intVal(row.RC4),
		intVal(row.RC5),
		intVal(row.RC6),
		intVal(row.RC7),
		intVal(row.InitLevel),
		boolVal(row.Xinetd),
		stringVal(row.User),
		boolVal(row.Enable),
		intVal(row.StartType),
		stringVal(row.Publisher),
		stringVal(row.ShowName),
	}
}
