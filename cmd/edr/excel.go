package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/processscan"
)

var excelHeaders = []string{
	"displayIp",
	"externalIpList",
	"internalIpList",
	"processExternalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"startTime",
	"version",
	"root",
	"prtCount",
	"Md5",
	"packageName",
	"packageVersion",
	"installByPm",
	"pid",
	"ppid",
	"path",
	"startArgs",
	"state",
	"uname",
	"uid",
	"gname",
	"gid",
	"tty",
	"name",
	"sessionId",
	"sessionName",
	"type",
	"description",
	"groups",
	"size",
}

func writeExcel(path string, results []processscan.ProcessInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "processes"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range excelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, proc := range results {
		row := r + 2
		values := excelRow(proc)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, row)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func excelRow(proc processscan.ProcessInfo) []any {
	return []any{
		stringVal(proc.DisplayIP),
		joinStrings(proc.ExternalIPList),
		joinStrings(proc.InternalIPList),
		joinStrings(proc.ProcessExternalIPList),
		int64Val(proc.BizGroupID),
		stringVal(proc.BizGroup),
		stringVal(proc.Remark),
		joinStrings(proc.HostTagList),
		stringVal(proc.Hostname),
		timeVal(proc.StartTime),
		stringVal(proc.Version),
		boolVal(proc.Root),
		intVal(proc.PrtCount),
		stringVal(proc.Md5),
		stringVal(proc.PackageName),
		stringVal(proc.PackageVersion),
		boolVal(proc.InstallByPm),
		intVal(proc.PID),
		intVal(proc.PPID),
		stringVal(proc.Path),
		stringVal(proc.StartArgs),
		stringVal(proc.State),
		stringVal(proc.Uname),
		int64Val(proc.UID),
		stringVal(proc.Gname),
		int64Val(proc.GID),
		stringVal(proc.TTY),
		stringVal(proc.Name),
		intVal(proc.SessionID),
		stringVal(proc.SessionName),
		intVal(proc.Type),
		stringVal(proc.Description),
		joinStrings(proc.Groups),
		int64Val(proc.Size),
	}
}

func stringVal(val *string) string {
	if val == nil {
		return ""
	}
	return *val
}

func intVal(val *int) any {
	if val == nil {
		return ""
	}
	return *val
}

func int64Val(val *int64) any {
	if val == nil {
		return ""
	}
	return *val
}

func float64Val(val *float64) any {
	if val == nil {
		return ""
	}
	return *val
}

func boolVal(val *bool) any {
	if val == nil {
		return ""
	}
	return *val
}

func timeVal(val *time.Time) string {
	if val == nil {
		return ""
	}
	return val.Format(time.RFC3339)
}

func joinStrings(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return strings.Join(list, ",")
}
