## 1. CLI Entry And Argument Contracts

- [x] 1.1 Add `eventlog` top-level command routing in unified CLI command dispatch.
- [x] 1.2 Implement `eventlog` argument parsing for required time range, paging defaults, filter fields, and sort fields.
- [x] 1.3 Enforce collection-only behavior by rejecting `-r/--riskanalyze` and risk-only flags in `eventlog`.
- [x] 1.4 Integrate `eventlog` with global `-o/--output` emission path and format validation.
- [x] 1.5 Add CLI parsing/error-path tests for invalid ranges, invalid paging values, unsupported flags, and help behavior.

## 2. Eventlog Collection And Normalization Layer

- [x] 2.1 Create a new internal eventlog scan package with query params, normalized row model, and paged result model.
- [x] 2.2 Implement Windows collector using in-process log APIs/readers without launching external commands.
- [x] 2.3 Implement Linux collector using in-process log APIs/readers without launching external commands.
- [x] 2.4 Implement normalization mapping for `source`, `eventType`, `eventLevel`, `eventCode`, `eventAction`, and `result`, including `other` fallback.
- [x] 2.5 Implement stable `logId` generation with native-ID preference and deterministic fallback hashing.

## 3. Query Processing Semantics

- [x] 3.1 Implement request validation rules (`startTime/endTime`, `startTime <= endTime`, page bounds, page-size max).
- [x] 3.2 Implement deterministic filter semantics: AND across fields, OR within array-valued fields, keyword as additional AND.
- [x] 3.3 Implement sorting with default `timestamp desc` and deterministic tie-break behavior for stable pagination.
- [x] 3.4 Implement page slicing and `hasMore` calculation for aggregate result envelope.
- [x] 3.5 Implement `rawContent` policy: default exclusion, sensitive-key redaction, truncation, and truncation indicator when included.

## 4. Help, Compatibility, And Verification

- [x] 4.1 Update root help command listing to include `eventlog` while preserving existing section structure.
- [x] 4.2 Add module help output for `c-eyes eventlog -h` consistent with existing top-level module style.
- [x] 4.3 Add normalization and collector fixture tests covering Windows/Linux source variance and enum mapping.
- [x] 4.4 Add end-to-end tests for `eventlog` output envelope (`total/pageNo/pageSize/hasMore/rows`) across JSON/CSV/XLSX output paths.
- [x] 4.5 Run `openspec validate --strict --changes add-eventlog-module` and resolve all validation issues.
