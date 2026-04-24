package filescan

import (
	"crypto/md5"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxSectionEntropyBytes = 1 << 20
)

type binaryKind int

const (
	binaryUnknown binaryKind = iota
	binaryPE
	binaryELF
)

func binaryInfo(path string) *FileBinaryInfo {
	magic, kind := detectBinaryKind(path)
	if kind == binaryUnknown {
		return nil
	}

	info := &FileBinaryInfo{
		MagicBytes: magic,
	}

	switch kind {
	case binaryPE:
		fillPEBinaryInfo(info, path)
	case binaryELF:
		fillELFBinaryInfo(info, path)
	}

	return info
}

func detectBinaryKind(path string) (*string, binaryKind) {
	file, err := os.Open(path)
	if err != nil {
		return nil, binaryUnknown
	}
	defer file.Close()

	buf := make([]byte, 4)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, binaryUnknown
	}
	if n <= 0 {
		return nil, binaryUnknown
	}
	magicStr := formatHex(buf[:n])
	if n >= 2 && buf[0] == 'M' && buf[1] == 'Z' {
		return &magicStr, binaryPE
	}
	if n >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
		return &magicStr, binaryELF
	}
	return &magicStr, binaryUnknown
}

func formatHex(buf []byte) string {
	parts := make([]string, 0, len(buf))
	for _, b := range buf {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, " ")
}

func entropyFromBytes(data []byte) *float64 {
	if len(data) == 0 {
		return nil
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return &entropy
}

func fillPEBinaryInfo(info *FileBinaryInfo, path string) {
	peFile, err := pe.Open(path)
	if err != nil {
		return
	}
	defer peFile.Close()

	imports := peImports(peFile)
	if len(imports) > 0 {
		info.ImportedLibraries = imports
	}

	sections := peSections(peFile)
	if len(sections) > 0 {
		info.SectionsInfo = sections
	}

	if info.VersionInfo == nil {
		if ver := peVersionInfo(path); ver != nil {
			info.VersionInfo = ver
		}
	}
}

func fillELFBinaryInfo(info *FileBinaryInfo, path string) {
	elfFile, err := elf.Open(path)
	if err != nil {
		return
	}
	defer elfFile.Close()

	imports := elfImports(elfFile)
	if len(imports) > 0 {
		info.ImportedLibraries = imports
	}

	sections := elfSections(elfFile)
	if len(sections) > 0 {
		info.SectionsInfo = sections
	}
}

func peImports(peFile *pe.File) []FileImport {
	order := make([]string, 0)
	seen := make(map[string]struct{})
	names := make(map[string]string)
	functions := make(map[string][]string)

	if syms, err := safePEImportedSymbols(peFile); err == nil {
		for _, sym := range syms {
			parts := strings.SplitN(sym, ":", 2)
			if len(parts) != 2 {
				continue
			}
			dll := strings.TrimSpace(parts[0])
			fn := strings.TrimSpace(parts[1])
			if dll == "" || fn == "" {
				continue
			}
			key := strings.ToLower(dll)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				order = append(order, key)
				names[key] = dll
			}
			functions[key] = append(functions[key], fn)
		}
	}

	if len(order) == 0 {
		if libs, err := safePEImportedLibraries(peFile); err == nil {
			for _, lib := range libs {
				lib = strings.TrimSpace(lib)
				if lib == "" {
					continue
				}
				key := strings.ToLower(lib)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				order = append(order, key)
				names[key] = lib
			}
		}
	}

	imports := make([]FileImport, 0, len(order))
	for _, key := range order {
		name := names[key]
		nameCopy := name
		imports = append(imports, FileImport{
			Dll:       &nameCopy,
			Functions: functions[key],
		})
	}
	return imports
}

func peSections(peFile *pe.File) []FileSectionInfo {
	sections := make([]FileSectionInfo, 0, len(peFile.Sections))
	for _, section := range peFile.Sections {
		if section == nil {
			continue
		}
		name := strings.TrimRight(section.Name, "\x00")
		nameCopy := name
		size := int64(section.Size)
		sec := FileSectionInfo{
			Name: &nameCopy,
			Size: &size,
		}
		if data, err := section.Data(); err == nil && len(data) > 0 {
			if len(data) > maxSectionEntropyBytes {
				data = data[:maxSectionEntropyBytes]
			}
			sec.Entropy = entropyFromBytes(data)
		}
		sections = append(sections, sec)
	}
	return sections
}

func elfImports(elfFile *elf.File) []FileImport {
	order := make([]string, 0)
	seen := make(map[string]struct{})
	functions := make(map[string][]string)

	if syms, err := elfFile.ImportedSymbols(); err == nil {
		for _, sym := range syms {
			lib := strings.TrimSpace(sym.Library)
			fn := strings.TrimSpace(sym.Name)
			if lib == "" {
				continue
			}
			key := strings.ToLower(lib)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				order = append(order, key)
			}
			if fn != "" {
				functions[key] = append(functions[key], fn)
			}
		}
	}

	if len(order) == 0 {
		if libs, err := elfFile.ImportedLibraries(); err == nil {
			for _, lib := range libs {
				lib = strings.TrimSpace(lib)
				if lib == "" {
					continue
				}
				key := strings.ToLower(lib)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				order = append(order, key)
			}
		}
	}

	imports := make([]FileImport, 0, len(order))
	for _, key := range order {
		libName := key
		if base := filepath.Base(key); base != "" {
			libName = base
		}
		nameCopy := libName
		imports = append(imports, FileImport{
			Dll:       &nameCopy,
			Functions: functions[key],
		})
	}
	return imports
}

func elfSections(elfFile *elf.File) []FileSectionInfo {
	sections := make([]FileSectionInfo, 0, len(elfFile.Sections))
	for _, section := range elfFile.Sections {
		if section == nil {
			continue
		}
		name := section.Name
		nameCopy := name
		size := int64(section.Size)
		sec := FileSectionInfo{
			Name: &nameCopy,
			Size: &size,
		}
		if data, err := section.Data(); err == nil && len(data) > 0 {
			if len(data) > maxSectionEntropyBytes {
				data = data[:maxSectionEntropyBytes]
			}
			sec.Entropy = entropyFromBytes(data)
		}
		sections = append(sections, sec)
	}
	return sections
}

func imphashForFile(path string) *string {
	peFile, err := pe.Open(path)
	if err == nil {
		defer peFile.Close()
		return peImphash(peFile)
	}

	elfFile, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer elfFile.Close()
	return elfImphash(elfFile)
}

func peImphash(peFile *pe.File) *string {
	if peFile == nil {
		return nil
	}
	syms, err := safePEImportedSymbols(peFile)
	if err != nil || len(syms) == 0 {
		return nil
	}
	parts := make([]string, 0, len(syms))
	for _, sym := range syms {
		fields := strings.SplitN(sym, ":", 2)
		if len(fields) != 2 {
			continue
		}
		dll := strings.TrimSpace(fields[0])
		fn := strings.TrimSpace(fields[1])
		if dll == "" || fn == "" {
			continue
		}
		dll = strings.ToLower(dll)
		dll = strings.TrimSuffix(dll, filepath.Ext(dll))
		fn = strings.ToLower(fn)
		parts = append(parts, dll+"."+fn)
	}
	return md5Hex(parts)
}

func safePEImportedSymbols(peFile *pe.File) (syms []string, err error) {
	if peFile == nil {
		return nil, nil
	}
	return safeCallStringList("PE imported symbols", peFile.ImportedSymbols)
}

func safePEImportedLibraries(peFile *pe.File) (libs []string, err error) {
	if peFile == nil {
		return nil, nil
	}
	return safeCallStringList("PE imported libraries", peFile.ImportedLibraries)
}

func safeCallStringList(op string, call func() ([]string, error)) (out []string, err error) {
	if call == nil {
		return nil, nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("read %s panic: %v", op, r)
			out = nil
		}
	}()
	return call()
}

func elfImphash(elfFile *elf.File) *string {
	if elfFile == nil {
		return nil
	}
	syms, err := elfFile.ImportedSymbols()
	if err != nil || len(syms) == 0 {
		return nil
	}
	parts := make([]string, 0, len(syms))
	for _, sym := range syms {
		lib := normalizeELFLib(sym.Library)
		fn := normalizeELFFunction(sym.Name)
		if lib == "" || fn == "" {
			continue
		}
		parts = append(parts, lib+"."+fn)
	}
	if len(parts) == 0 {
		return nil
	}
	sort.Strings(parts)
	return md5Hex(parts)
}

func normalizeELFLib(lib string) string {
	lib = strings.TrimSpace(lib)
	if lib == "" {
		return ""
	}
	lib = strings.ToLower(filepath.Base(lib))
	switch {
	case strings.Contains(lib, ".so."):
		parts := strings.SplitN(lib, ".so.", 2)
		if len(parts) > 0 {
			lib = parts[0] + ".so"
		}
	case strings.HasSuffix(lib, ".so"):
		// keep as-is
	case strings.HasSuffix(lib, ".dylib"):
		// keep as-is
	default:
		// keep as-is for uncommon names
	}
	return lib
}

func normalizeELFFunction(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if idx := strings.Index(name, "@"); idx >= 0 {
		name = name[:idx]
	}
	return strings.ToLower(name)
}

func md5Hex(parts []string) *string {
	if len(parts) == 0 {
		return nil
	}
	raw := strings.Join(parts, ",")
	hash := md5.Sum([]byte(raw))
	val := hex.EncodeToString(hash[:])
	return &val
}
