package riskanalysis

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func NormalizeTarget(record ScanRecord, now time.Time) TargetMetadata {
	raw := record.Raw
	meta := TargetMetadata{
		ScanID:    scanIDFrom(raw),
		Timestamp: now.UTC(),
		Hashes:    extractHashes(raw),
	}
	if host, ok := stringFrom(raw, "hostname", "hostName", "Hostname"); ok {
		meta.SourceHostname = host
	}

	meta.TargetType = targetTypeFrom(raw)
	meta.TargetPath = targetPathFrom(raw)

	if pid, ok := intFrom(raw, "pid", "PID"); ok {
		meta.PID = &pid
	}

	if size, ok := int64From(raw, "file_size", "fileSize", "size"); ok {
		meta.FileSize = &size
	}

	if meta.FileSize == nil {
		if basic, ok := mapFrom(raw, "basic_info", "basicInfo"); ok {
			if size, ok := int64From(basic, "file_size_bytes", "fileSizeBytes"); ok {
				meta.FileSize = &size
			}
		}
	}

	if meta.TargetPath == "" {
		if basic, ok := mapFrom(raw, "basic_info", "basicInfo"); ok {
			if path, ok := stringFrom(basic, "file_path", "filePath"); ok {
				meta.TargetPath = path
			}
			if meta.TargetPath == "" {
				if name, ok := stringFrom(basic, "file_name", "fileName"); ok {
					meta.TargetPath = name
				}
			}
		}
	}

	if meta.TargetType == "" {
		meta.TargetType = "file"
	}

	meta.Signature = signatureFrom(raw)
	meta.Process = processFrom(raw)
	if product, ok := stringFrom(raw, "product_name", "productName"); ok {
		meta.ProductName = product
	}
	if meta.ProductName == "" {
		if version, ok := mapFrom(raw, "version_info", "versionInfo", "binary_info", "binaryInfo"); ok {
			if product, ok := stringFrom(version, "file_description", "fileDescription", "product_name", "productName"); ok {
				meta.ProductName = product
			}
		}
	}

	return meta
}

func scanIDFrom(raw map[string]any) string {
	if raw == nil {
		return newScanID()
	}
	if id, ok := stringFrom(raw, "scan_id", "scanId", "scanID"); ok {
		return id
	}
	return newScanID()
}

func targetTypeFrom(raw map[string]any) string {
	if raw == nil {
		return ""
	}
	if targetType, ok := stringFrom(raw, "target_type", "targetType"); ok {
		return targetType
	}
	if _, ok := raw["basic_info"]; ok {
		return "file"
	}
	if _, ok := raw["basicInfo"]; ok {
		return "file"
	}
	if _, ok := raw["pid"]; ok {
		return "process"
	}
	if _, ok := raw["PID"]; ok {
		return "process"
	}
	return ""
}

func targetPathFrom(raw map[string]any) string {
	if raw == nil {
		return ""
	}
	if path, ok := stringFrom(raw, "target_path", "targetPath"); ok {
		return path
	}
	if path, ok := stringFrom(raw, "path", "Path"); ok {
		return path
	}
	if basic, ok := mapFrom(raw, "basic_info", "basicInfo"); ok {
		if path, ok := stringFrom(basic, "file_path", "filePath"); ok {
			return path
		}
	}
	return ""
}

func extractHashes(raw map[string]any) Hashes {
	var hashes Hashes
	if raw == nil {
		return hashes
	}
	if hashMap, ok := mapFrom(raw, "hashes"); ok {
		if val, ok := stringFrom(hashMap, "sha256", "sha-256", "Sha256"); ok {
			hashes.Sha256 = val
		}
		if val, ok := stringFrom(hashMap, "md5", "MD5", "Md5"); ok {
			hashes.Md5 = val
		}
		if val, ok := stringFrom(hashMap, "sha1", "Sha1", "SHA1", "sha-1"); ok {
			hashes.Sha1 = val
		}
	}
	if hashes.Md5 == "" {
		if val, ok := stringFrom(raw, "md5", "Md5", "MD5"); ok {
			hashes.Md5 = val
		}
	}
	return hashes
}

func signatureFrom(raw map[string]any) SignatureMetadata {
	var sig SignatureMetadata
	if raw == nil {
		return sig
	}
	if v, ok := boolFromMap(raw, "signature_valid", "signatureValid"); ok {
		sig.Valid = &v
	}
	if s, ok := stringFrom(raw, "signer_subject", "signerSubject", "signer"); ok {
		sig.Signer = s
	}
	if s, ok := stringFrom(raw, "certificate_thumbprint", "certificateThumbprint", "thumbprint"); ok {
		sig.Thumbprint = s
	}
	if s, ok := stringFrom(raw, "certificate_serial", "certificateSerial", "serial"); ok {
		sig.Serial = s
	}
	if s, ok := stringFrom(raw, "certificate_issuer", "certificateIssuer", "issuer"); ok {
		sig.Issuer = s
	}

	if nested, ok := mapFrom(raw, "signature"); ok {
		if sig.Valid == nil {
			if v, ok := boolFromMap(nested, "signature_valid", "signatureValid", "valid"); ok {
				sig.Valid = &v
			}
		}
		if sig.Signer == "" {
			if s, ok := stringFrom(nested, "signer_subject", "signerSubject", "signer"); ok {
				sig.Signer = s
			}
		}
		if sig.Thumbprint == "" {
			if s, ok := stringFrom(nested, "certificate_thumbprint", "certificateThumbprint", "thumbprint"); ok {
				sig.Thumbprint = s
			}
		}
		if sig.Serial == "" {
			if s, ok := stringFrom(nested, "certificate_serial", "certificateSerial", "serial"); ok {
				sig.Serial = s
			}
		}
		if sig.Issuer == "" {
			if s, ok := stringFrom(nested, "certificate_issuer", "certificateIssuer", "issuer"); ok {
				sig.Issuer = s
			}
		}
	}
	return sig
}

func processFrom(raw map[string]any) ProcessMetadata {
	var p ProcessMetadata
	if raw == nil {
		return p
	}
	if s, ok := stringFrom(raw, "process_name", "processName", "name"); ok {
		p.Name = s
	}
	if s, ok := stringFrom(raw, "start_args", "startArgs", "command_line", "commandLine", "cmdline"); ok {
		p.Command = s
	}
	if v, ok := intFrom(raw, "ppid", "parent_pid", "parentPid"); ok {
		p.ParentPID = &v
	}
	if s, ok := stringFrom(raw, "parent_name", "parentName"); ok {
		p.ParentName = s
	}
	if s, ok := stringFrom(raw, "parent_path", "parentPath"); ok {
		p.ParentPath = s
	}
	return p
}

func boolFromMap(raw map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		val, ok := raw[key]
		if !ok {
			continue
		}
		switch v := val.(type) {
		case bool:
			return v, true
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "1", "true", "yes":
				return true, true
			case "0", "false", "no":
				return false, true
			}
		}
	}
	return false, false
}

func mapFrom(raw map[string]any, keys ...string) (map[string]any, bool) {
	for _, key := range keys {
		if val, ok := raw[key]; ok {
			if nested, ok := val.(map[string]any); ok {
				return nested, true
			}
		}
	}
	return nil, false
}

func stringFrom(raw map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if val, ok := raw[key]; ok {
			if str, ok := toString(val); ok {
				return str, true
			}
		}
	}
	return "", false
}

func intFrom(raw map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if val, ok := raw[key]; ok {
			if number, ok := toInt(val); ok {
				return number, true
			}
		}
	}
	return 0, false
}

func int64From(raw map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		if val, ok := raw[key]; ok {
			if number, ok := toInt64(val); ok {
				return number, true
			}
		}
	}
	return 0, false
}

func toString(val any) (string, bool) {
	switch v := val.(type) {
	case string:
		if v == "" {
			return "", false
		}
		return v, true
	case json.Number:
		return v.String(), true
	case fmt.Stringer:
		return v.String(), true
	}
	return "", false
}

func toInt(val any) (int, bool) {
	switch v := val.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case json.Number:
		parsed, err := v.Int64()
		if err == nil {
			return int(parsed), true
		}
	case string:
		parsed, err := json.Number(v).Int64()
		if err == nil {
			return int(parsed), true
		}
	}
	return 0, false
}

func toInt64(val any) (int64, bool) {
	switch v := val.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case json.Number:
		parsed, err := v.Int64()
		if err == nil {
			return parsed, true
		}
	case string:
		parsed, err := json.Number(v).Int64()
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func newScanID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("scan-%d", time.Now().UnixNano())
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(buf[0:4]),
		hex.EncodeToString(buf[4:6]),
		hex.EncodeToString(buf[6:8]),
		hex.EncodeToString(buf[8:10]),
		hex.EncodeToString(buf[10:16]),
	)
}
