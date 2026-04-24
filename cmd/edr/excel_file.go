package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/filescan"
)

var fileScanHeaders = []string{
	"scan_mode",
	"smart_enabled",
	"source",
	"hostname",
	"displayIp",
	"externalIpList",
	"internalIpList",
	"basic_info.file_path",
	"basic_info.file_name",
	"basic_info.file_size_bytes",
	"basic_info.creation_time",
	"basic_info.modification_time",
	"basic_info.access_time",
	"basic_info.attributes",
	"basic_info.owner",
	"basic_info.group",
	"basic_info.mode",
	"hashes.sha256",
	"hashes.imphash",
	"signature.is_signed",
	"signature.signature_valid",
	"signature.signer_subject",
	"signature.certificate_thumbprint",
	"binary_info.magic_bytes",
	"binary_info.imported_libraries",
	"binary_info.sections_info",
	"binary_info.version_info",
	"context.motw_zone_id",
	"context.download_url",
}

func writeFileExcel(path string, results []filescan.FileScanResult) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "files"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range fileScanHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, result := range results {
		row := r + 2
		values := fileExcelRow(result)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, row)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func fileExcelRow(result filescan.FileScanResult) []any {
	var (
		basic     = result.BasicInfo
		hashes    = result.Hashes
		signature = result.Signature
		binary    = result.BinaryInfo
		context   = result.Context
	)

	var (
		filePath, fileName    *string
		fileSize              *int64
		creationTime, modTime *time.Time
		accessTime            *time.Time
		attributes            []string
		owner, group, mode    *string
	)
	if basic != nil {
		filePath = basic.FilePath
		fileName = basic.FileName
		fileSize = basic.FileSizeBytes
		creationTime = basic.CreationTime
		modTime = basic.ModificationTime
		accessTime = basic.AccessTime
		attributes = basic.Attributes
		owner = basic.Owner
		group = basic.Group
		mode = basic.Mode
	}

	var (
		sha256, imphash *string
	)
	if hashes != nil {
		sha256 = hashes.Sha256
		imphash = hashes.Imphash
	}

	var (
		isSigned, sigValid *bool
		signerSubject      *string
		certThumbprint     *string
	)
	if signature != nil {
		isSigned = signature.IsSigned
		sigValid = signature.SignatureValid
		signerSubject = signature.SignerSubject
		certThumbprint = signature.CertificateThumbprint
	}

	var (
		magicBytes  *string
		imported    []filescan.FileImport
		sections    []filescan.FileSectionInfo
		versionInfo *filescan.FileVersionInfo
	)
	if binary != nil {
		magicBytes = binary.MagicBytes
		imported = binary.ImportedLibraries
		sections = binary.SectionsInfo
		versionInfo = binary.VersionInfo
	}

	var (
		motwZoneID  *int
		downloadURL *string
	)
	if context != nil {
		motwZoneID = context.MotwZoneID
		downloadURL = context.DownloadURL
	}

	return []any{
		scanModeVal(result.ScanMode),
		boolVal(result.SmartEnabled),
		stringVal(result.Source),
		stringVal(result.Hostname),
		stringVal(result.DisplayIP),
		joinStrings(result.ExternalIPList),
		joinStrings(result.InternalIPList),
		stringVal(filePath),
		stringVal(fileName),
		int64Val(fileSize),
		timeVal(creationTime),
		timeVal(modTime),
		timeVal(accessTime),
		joinStrings(attributes),
		stringVal(owner),
		stringVal(group),
		stringVal(mode),
		stringVal(sha256),
		stringVal(imphash),
		boolVal(isSigned),
		boolVal(sigValid),
		stringVal(signerSubject),
		stringVal(certThumbprint),
		stringVal(magicBytes),
		jsonCell(imported),
		jsonCell(sections),
		jsonCell(versionInfo),
		intVal(motwZoneID),
		stringVal(downloadURL),
	}
}

func scanModeVal(val *filescan.ScanMode) string {
	if val == nil {
		return ""
	}
	return string(*val)
}

func jsonCell(value any) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case []filescan.FileImport:
		if len(v) == 0 {
			return ""
		}
	case []filescan.FileSectionInfo:
		if len(v) == 0 {
			return ""
		}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	if string(payload) == "null" || string(payload) == "[]" {
		return ""
	}
	return string(payload)
}
