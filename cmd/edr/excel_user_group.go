package main

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/usergroupscan"
)

var userGroupExcelHeaders = []string{
	"displayIp",
	"externalIpList",
	"internalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"name",
	"gid",
	"members",
	"description",
}

func writeUserGroupExcel(path string, rows []usergroupscan.UserGroupInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "user-groups"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range userGroupExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := userGroupExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func userGroupExcelRow(row usergroupscan.UserGroupInfo) []any {
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
		int64Val(row.GID),
		toJSONText(row.Members),
		stringVal(row.Description),
	}
}
