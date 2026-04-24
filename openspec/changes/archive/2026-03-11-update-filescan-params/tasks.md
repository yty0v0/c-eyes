## 1. Schema & Output

- [x] 1.1 Update `internal/filescan/types.go` with nested result structs and snake_case JSON tags
- [x] 1.2 Update `cmd/edr/excel_file.go` headers and row mapping (flattened `group.field`, JSON string for arrays/objects)
- [x] 1.3 Adjust result assembly/reporting to populate the new output schema while preserving scan metadata

## 2. Data Collection

- [x] 2.1 Implement basic metadata collection (path/name/size/timestamps/attributes or owner/group/mode)
- [x] 2.2 Extend hash collection to include `ssdeep` and `imphash` with PE/ELF gating
- [x] 2.3 Add signature collection (Windows) and no-op stubs for non-Windows
- [x] 2.4 Add binary info extraction (magic bytes, entropy, sections, imports, version info)
- [x] 2.5 Add context collection (MOTW zone id and download URL on Windows)

## 3. Docs & Verification

- [x] 3.1 Update docs/examples to reflect new JSON/Excel output structure
- [x] 3.2 Add or update tests for JSON/Excel output mapping and null handling

## 4. Info-Only Output Cleanup

- [x] 4.1 Remove analysis-only output fields (`detected_by`, `trusted_signature`)
- [x] 4.2 Drop heavy collection fields (`md5`, `ssdeep`, `global_entropy`) from output and mapping
