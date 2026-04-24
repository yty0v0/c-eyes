package riskanalysis

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/xuri/excelize/v2"
)

// LoadScanRecords reads scan results from JSON (array/NDJSON), CSV, or Excel files.
func LoadScanRecords(path string) ([]ScanRecord, error) {
	if path == "" {
		return nil, fmt.Errorf("input path is empty")
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		return loadScanRecordsFromCSV(path)
	case ".xlsx", ".xlsm", ".xltx", ".xltm":
		return loadScanRecordsFromExcel(path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return decodeScanRecords(bufio.NewReader(file))
}

func decodeScanRecords(reader *bufio.Reader) ([]ScanRecord, error) {
	first, err := peekNonSpace(reader)
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("empty input")
		}
		return nil, err
	}

	decoder := json.NewDecoder(reader)
	decoder.UseNumber()

	if first == '[' {
		return decodeJSONArray(decoder)
	}
	return decodeJSONStream(decoder)
}

func decodeJSONArray(decoder *json.Decoder) ([]ScanRecord, error) {
	tok, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '[' {
		return nil, fmt.Errorf("expected JSON array")
	}

	records := make([]ScanRecord, 0)
	for decoder.More() {
		var obj map[string]any
		if err := decoder.Decode(&obj); err != nil {
			return nil, err
		}
		if obj == nil {
			continue
		}
		records = append(records, ScanRecord{Raw: obj})
	}

	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return records, nil
}

func decodeJSONStream(decoder *json.Decoder) ([]ScanRecord, error) {
	records := make([]ScanRecord, 0)
	for {
		var obj map[string]any
		err := decoder.Decode(&obj)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if obj == nil {
			continue
		}
		records = append(records, ScanRecord{Raw: obj})
	}
	return records, nil
}

func peekNonSpace(reader *bufio.Reader) (byte, error) {
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if !unicode.IsSpace(rune(b)) {
			_ = reader.UnreadByte()
			return b, nil
		}
	}
}

func loadScanRecordsFromExcel(path string) ([]ScanRecord, error) {
	file, err := excelize.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	sheets := file.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("excel input has no sheets")
	}

	rows, err := file.GetRows(sheets[0])
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty excel input")
	}

	headers := rows[0]
	records := make([]ScanRecord, 0, len(rows)-1)
	for i := 1; i < len(rows); i++ {
		row := rows[i]
		raw := map[string]any{}
		nonEmpty := false
		for col := 0; col < len(headers); col++ {
			header := strings.TrimSpace(headers[col])
			if header == "" || col >= len(row) {
				continue
			}
			cell := strings.TrimSpace(row[col])
			if cell == "" {
				continue
			}
			nonEmpty = true
			setNestedField(raw, header, parseExcelCellValue(cell))
		}
		if !nonEmpty {
			continue
		}
		records = append(records, ScanRecord{Raw: raw})
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no data rows found in excel input")
	}
	return records, nil
}

func loadScanRecordsFromCSV(path string) ([]ScanRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty csv input")
	}

	headers := rows[0]
	if len(headers) > 0 {
		headers[0] = trimUTF8BOM(headers[0])
	}

	records := make([]ScanRecord, 0, len(rows)-1)
	for i := 1; i < len(rows); i++ {
		row := rows[i]
		raw := map[string]any{}
		nonEmpty := false

		for col := 0; col < len(headers); col++ {
			header := strings.TrimSpace(headers[col])
			if header == "" || col >= len(row) {
				continue
			}
			cell := strings.TrimSpace(row[col])
			if cell == "" {
				continue
			}
			nonEmpty = true
			setNestedField(raw, header, parseExcelCellValue(cell))
		}

		if !nonEmpty {
			continue
		}
		records = append(records, ScanRecord{Raw: raw})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no data rows found in csv input")
	}
	return records, nil
}

func parseExcelCellValue(raw string) any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if (strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}")) || (strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]")) {
		var value any
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err == nil {
			return value
		}
	}

	switch strings.ToLower(raw) {
	case "true":
		return true
	case "false":
		return false
	}

	if intVal, err := json.Number(raw).Int64(); err == nil {
		return intVal
	}
	if floatVal, err := json.Number(raw).Float64(); err == nil {
		return floatVal
	}
	return raw
}

func trimUTF8BOM(value string) string {
	return strings.TrimPrefix(value, "\uFEFF")
}

func setNestedField(root map[string]any, key string, value any) {
	parts := strings.Split(key, ".")
	current := root
	for i := 0; i < len(parts); i++ {
		part := strings.TrimSpace(parts[i])
		if part == "" {
			return
		}
		if i == len(parts)-1 {
			current[part] = value
			return
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
}
