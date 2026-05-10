## 1. CLI Target Model

- [x] 1.1 Update `sbom` argument parsing to accept exactly one mutually exclusive target selector from `-p/--path`, `--image`, `--image-archive`, and `--oci-layout`
- [x] 1.2 Update SBOM help/usage text to document the new target selectors and collection-only restrictions
- [x] 1.3 Add parser validation tests for missing target, multiple targets, and valid per-target invocation

## 2. Native Image Collection

- [x] 2.1 Introduce internal SBOM image target adapters for local image archives and OCI layouts
- [x] 2.2 Introduce native `--image` collection plumbing that avoids external command execution and returns explicit unsupported-backend errors when native collection is unavailable
- [x] 2.3 Route image-derived package inventory results into existing SBOM document generation flow without adding vulnerability analysis behavior

## 3. Collection Scope and Output Integrity

- [x] 3.1 Preserve existing filesystem `-p/--path` behavior while removing global path-only requirement from SBOM mode
- [x] 3.2 Add tests verifying image collection output remains inventory-only and excludes risk/vulnerability verdict fields
- [x] 3.3 Validate that explicit JSON output and default `result*.json` behavior remain intact for all SBOM target modes

## 4. Verification

- [x] 4.1 Run targeted CLI/SBOM tests covering filesystem mode and all image target parameter paths
- [x] 4.2 Run `openspec validate --strict --no-interactive` and fix any spec or artifact issues
