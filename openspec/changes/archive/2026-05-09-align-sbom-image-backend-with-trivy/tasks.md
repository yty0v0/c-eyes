## 1. Backend Alignment Plan

- [x] 1.1 Compare the current `internal/sbom` image backend layer against the reference tool's image backend package boundaries and identify the minimal set to align or port
- [x] 1.2 Introduce an isolated backend package/adapter boundary so reference-aligned logic is separated from CLI and SBOM document-generation code

## 2. Implementation

- [x] 2.1 Replace or refactor custom archive / OCI / image-reference backend logic toward the reference-aligned implementation model
- [x] 2.2 Preserve collection-only behavior and current output contracts while reconnecting the aligned backend to the existing SBOM generation flow
- [x] 2.3 Add or update comparison-focused tests to verify backend parity improvements without regressing supported modes

## 3. Verification

- [x] 3.1 Run focused SBOM and CLI regressions across path, archive, OCI, and image-reference modes
- [x] 3.2 Run `openspec validate --strict --no-interactive align-sbom-image-backend-with-trivy`
- [x] 3.3 Record any remaining parity gaps that require real runtime success-path environments
