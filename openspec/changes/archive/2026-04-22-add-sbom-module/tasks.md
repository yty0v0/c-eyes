## 1. SBOM Module Integration

- [x] 1.1 Import/adapt `C:\Users\Administrator\Desktop\sbom` code into repository internal package layout (e.g., `internal/sbom`) and resolve package/import paths
- [x] 1.2 Add/update Go dependencies required by integrated SBOM implementation and ensure `go mod tidy` is clean
- [x] 1.3 Implement a stable SBOM service entrypoint that executes collection and returns SBOM document data for CLI serialization

## 2. Unified CLI Command Wiring

- [x] 2.1 Add `sbom` route handling in `cmd/edr/unified_cli.go` root dispatcher
- [x] 2.2 Implement `sbom` argument parser with required `-p/--path`, `--format` support (`xspdx-json|spdx-json`), and default `xspdx-json`
- [x] 2.3 Add collection-only guardrails for `sbom` to reject `-r/--riskanalyze` and risk options with English error messages
- [x] 2.4 Extend help output (`usage` + subcommand help) to include `sbom` command and SBOM-specific options/notes

## 3. SBOM Output Behavior

- [x] 3.1 Implement SBOM command output policy to accept only `.json` when explicit `-o/--output` is provided
- [x] 3.2 Implement SBOM-specific default output auto-naming (`result.json`, `result1.json`, `resultN.json`) when `-o` is omitted
- [x] 3.3 Reuse existing global output emit path for JSON write while isolating SBOM-specific suffix/default logic to SBOM branch

## 4. Validation, Tests, and Docs

- [x] 4.1 Add/adjust unit tests for SBOM parse rules, format validation, collection-only behavior, help text, and `result*.json` auto-increment behavior
- [x] 4.2 Normalize `docs/sbom.md` to UTF-8 and update requirement text to match final command/output semantics
- [x] 4.3 Run `openspec validate --strict --no-interactive` and targeted Go tests; fix failures until green
