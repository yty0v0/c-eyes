## 1. CLI Contract and Parameter Validation

- [x] 1.1 Add `web-framework-scan` command entry to the CLI command tree.
- [x] 1.2 Implement request parameter parsing for `groups`, `hostname`, `ip`, `name`, `version`, `type`, and `serverName`.
- [x] 1.3 Add validation for array filters and fuzzy-match filters, and return non-zero exit status on invalid input.

## 2. Domain Model and Normalization Pipeline

- [x] 2.1 Define normalized `WebFrameRecord` and `JarRecord` models aligned with required output keys.
- [x] 2.2 Implement static-plus-dynamic merge pipeline with deduplication and conflict resolution.
- [x] 2.3 Integrate host metadata enrichment including `displayIp`, `internalIpList`, and `externalIpList`.

## 3. Cross-Platform Collectors

- [x] 3.1 Implement Windows collector using in-process APIs, config parsing, and file inspection without external command execution.
- [x] 3.2 Implement Linux collector using in-process data access, config parsing, and file inspection without external command execution.
- [x] 3.3 Map platform-specific findings to unified fields: `name`, `version`, `type`, `serverName`, `domainName`, `webAppDir`, `webRoot`, `workDir`, `jarCount`, and `jarList`.

## 4. Output Writers and Encoding

- [x] 4.1 Implement JSON writer for normalized framework records.
- [x] 4.2 Implement Excel writer with contract-aligned columns and UTF-8 compatible content.
- [x] 4.3 Ensure stable fallback behavior (null/empty array) when optional fields are unavailable.

## 5. Testing and Verification

- [x] 5.1 Add unit tests for parameter validation and combined filter behavior.
- [x] 5.2 Add collector tests for Windows/Linux fixtures covering static-plus-dynamic merging.
- [x] 5.3 Add schema tests for output keys, `jarList` sub-schema, and IP list-based fields.
- [x] 5.4 Add export tests to verify JSON/Excel parity and confirm no risk-analysis fields are emitted.
