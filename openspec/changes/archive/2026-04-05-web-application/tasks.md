## 1. CLI Contract and Validation

- [x] 1.1 Add `web-application-scan` command entry to the CLI command tree.
- [x] 1.2 Implement request parameter parsing for `groups`, `hostname`, `ip`, `version`, `appName`, `rootPath`, `webRoot`, `serverName`, and `domainName`.
- [x] 1.3 Add validation for array and fuzzy filter inputs and ensure invalid inputs return non-zero exit status.

## 2. Domain Model and Filter Pipeline

- [x] 2.1 Define normalized web application record model with stable output keys and plugin sub-schema.
- [x] 2.2 Implement in-memory filter composition for fuzzy and structured filters.
- [x] 2.3 Integrate host metadata enrichment including `displayIp`, `internalIpList`, and `externalIpList`.

## 3. Cross-Platform Collectors

- [x] 3.1 Implement Windows web application collector using in-process APIs/config parsing without external commands.
- [x] 3.2 Implement Linux web application collector using config/file parsing without external commands.
- [x] 3.3 Map platform-specific metadata to unified `serverName`, path, version, domain, and plugin fields.

## 4. Output Writers

- [x] 4.1 Implement JSON writer for normalized record output.
- [x] 4.2 Implement Excel writer with contract-aligned columns.
- [x] 4.3 Add null/empty-array fallback behavior to keep output schema stable.

## 5. Testing and Verification

- [x] 5.1 Add unit tests for parameter validation and filter behavior.
- [x] 5.2 Add collector tests with Windows/Linux fixtures, including plugin normalization.
- [x] 5.3 Add export tests to verify JSON/Excel schema parity and IP list serialization.
- [x] 5.4 Add integration test to verify output excludes risk-analysis fields.
