package main

import (
	"encoding/json"
	"fmt"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/accountscan"
)

var accountExcelHeaders = []string{
	"displayIp",
	"connectionIp",
	"externalIpList",
	"internalIpList",
	"bizGroupId",
	"bizGroup",
	"remark",
	"hostTagList",
	"hostname",
	"uid",
	"gid",
	"groups",
	"name",
	"status",
	"home",
	"shell",
	"loginStatus",
	"lastLoginTime",
	"pwdMaxDays",
	"pwdMinDays",
	"pwdWarnDays",
	"sshAcl",
	"comment",
	"lastLoginTty",
	"lastLoginIp",
	"expireTime",
	"expired",
	"fullName",
	"sudoAccesses",
	"root",
	"description",
	"type",
	"lastChangPwdTime",
	"accountLoginType",
	"interactiveLoginType",
	"passwordInactiveDays",
	"sudo",
	"authorizedKeys",
}

func writeAccountExcel(path string, rows []accountscan.AccountInfo) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "accounts"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range accountExcelHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, row := range rows {
		index := r + 2
		values := accountExcelRow(row)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, index)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func accountExcelRow(row accountscan.AccountInfo) []any {
	return []any{
		stringVal(row.DisplayIP),
		stringVal(row.ConnectionIP),
		joinStrings(row.ExternalIPList),
		joinStrings(row.InternalIPList),
		int64Val(row.BizGroupID),
		stringVal(row.BizGroup),
		stringVal(row.Remark),
		joinStrings(row.HostTagList),
		stringVal(row.Hostname),
		int64Val(row.UID),
		int64Val(row.GID),
		joinStrings(row.Groups),
		stringVal(row.Name),
		intVal(row.Status),
		stringVal(row.Home),
		stringVal(row.Shell),
		intVal(row.LoginStatus),
		timeVal(row.LastLoginTime),
		intVal(row.PwdMaxDays),
		intVal(row.PwdMinDays),
		intVal(row.PwdWarnDays),
		stringVal(row.SSHACL),
		stringVal(row.Comment),
		stringVal(row.LastLoginTTY),
		stringVal(row.LastLoginIP),
		timeVal(row.ExpireTime),
		boolVal(row.Expired),
		stringVal(row.FullName),
		toJSONText(row.SudoAccesses),
		boolVal(row.Root),
		stringVal(row.Description),
		intVal(row.Type),
		timeVal(row.LastChangPwdTime),
		intVal(row.AccountLoginType),
		intVal(row.InteractiveLoginType),
		intVal(row.PasswordInactiveDays),
		boolVal(row.Sudo),
		toJSONText(row.AuthorizedKeys),
	}
}

func toJSONText(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}
