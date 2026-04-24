package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/scheduledtaskscan"
)

var scheduledTaskScanExcelHeaders = []string{
	"displayIp",
	"externalIpList",
	"internalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"user",
	"execTime",
	"execPath",
	"conf",
	"taskTime",
	"taskId",
	"taskType",
	"crondOpen",
}

func writeScheduledTaskScanExcel(path string, rows []scheduledtaskscan.ScheduledTaskInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "scheduled-task-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range scheduledTaskScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := scheduledTaskScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func scheduledTaskScanExcelRow(row scheduledtaskscan.ScheduledTaskInfo) []any {
	return []any{
		stringVal(row.DisplayIP),
		joinStrings(row.ExternalIPList),
		joinStrings(row.InternalIPList),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Hostname),
		stringVal(row.User),
		stringVal(row.ExecTime),
		stringVal(row.ExecPath),
		stringVal(row.Conf),
		timeVal(row.TaskTime),
		int64Val(row.TaskID),
		stringVal(row.TaskType),
		boolVal(row.CrondOpen),
	}
}
