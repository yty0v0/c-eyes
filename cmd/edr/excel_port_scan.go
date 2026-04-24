package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/portscan"
)

var portScanExcelHeaders = []string{
	"displayIp",
	"externalIpList",
	"internalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"proto",
	"port",
	"pid",
	"processName",
	"bindIp",
	"status",
}

func writePortScanExcel(path string, rows []portscan.PortInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "port-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range portScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := portScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func portScanExcelRow(row portscan.PortInfo) []any {
	return []any{
		stringVal(row.DisplayIP),
		joinStrings(row.ExternalIPList),
		joinStrings(row.InternalIPList),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Proto),
		intVal(row.Port),
		intVal(row.PID),
		stringVal(row.ProcessName),
		stringVal(row.BindIP),
		intVal(row.Status),
	}
}
