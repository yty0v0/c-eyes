package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/databasescan"
)

var databaseScanExcelHeaders = []string{
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
	"port",
	"protoType",
	"user",
	"bindIp",
	"confPath",
	"logPath",
	"dataDir",
	"pluginDir",
	"rest",
	"auth",
	"web",
	"webPort",
	"webAddress",
	"regionServer",
	"dbName",
	"loginModel",
	"auditLevel",
	"sysLogPath",
	"mainDbPath",
}

func writeDatabaseScanExcel(path string, rows []databasescan.DatabaseRecord) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "database-scan"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range databaseScanExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := databaseScanExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func databaseScanExcelRow(row databasescan.DatabaseRecord) []any {
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
		intVal(row.Port),
		stringVal(row.ProtoType),
		stringVal(row.User),
		stringVal(row.BindIP),
		stringVal(row.ConfPath),
		stringVal(row.LogPath),
		stringVal(row.DataDir),
		stringVal(row.PluginDir),
		boolVal(row.Rest),
		stringVal(row.Auth),
		boolVal(row.Web),
		intVal(row.WebPort),
		stringVal(row.WebAddress),
		joinStrings(row.RegionServer),
		stringVal(row.DBName),
		intVal(row.LoginModel),
		intVal(row.AuditLevel),
		stringVal(row.SysLogPath),
		stringVal(row.MainDBPath),
	}
}
