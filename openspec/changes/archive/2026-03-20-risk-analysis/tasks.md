## 1. Input & Models

- [x] 1.1 Define risk analysis data models for target metadata, risk assessment, and local/cloud sections
- [x] 1.2 Implement scan result file loader supporting JSON array/NDJSON with tolerant parsing for unknown fields

## 2. Mode & Orchestration

- [x] 2.1 Add CLI/config parameters for analysis mode (`local_only`, `cloud_only`, `hybrid`) and output format
- [x] 2.2 Implement analysis pipeline that routes local/cloud/hybrid execution and sets `analysis_mode`

## 3. Local YARA-X Integration

- [x] 3.1 Add `yara-x` dependency/build steps and a Go wrapper interface for embedded calls
- [x] 3.2 Implement rule loading and local matching to produce `local_matched` and `yara_results`

## 4. Cloud Threat Intel Query

- [x] 4.1 Implement cloud intel client with API key handling, rate limiting, and caching
- [x] 4.2 Map cloud responses into `cloud_analysis` fields and handle failures gracefully

## 5. Scoring & Output

- [x] 5.1 Implement weighted risk scoring and risk level mapping (0-20/21-50/51-80/81-100)
- [x] 5.2 Implement JSON output writer matching the required schema
- [x] 5.3 Implement Excel output writer with required columns

## 6. Tests & Docs

- [x] 6.1 Add unit tests for parsing, scoring, and mode selection
- [x] 6.2 Add integration tests using sample scan results and stubbed cloud responses
- [x] 6.3 Update usage docs and examples for risk analysis modes and outputs

## 7. Input Source Expansion

- [x] 7.1 Add direct risk-analysis sources: `-file`, `-dir -r`, `-pid`, `-pname`
- [x] 7.2 Enforce input-source mutual exclusion and parameter validation rules
- [x] 7.3 Support Excel scan-result input parsing in risk analysis loader

## 8. Local Safety & Fallback

- [x] 8.1 Add cross-host protection with hostname/hash verification before path-based local YARA match
- [x] 8.2 Add record-level fallback fields (`local_fallback`, `local_fallback_reason`) for local skip/error paths
- [x] 8.3 Enforce mode policy: `local_only` hard-fail without YARA, `hybrid` auto-fallback to cloud-only

## 9. Process Memory & YARA Runtime

- [x] 9.1 Add optional process-memory analysis mode and `process_memory` target record generation
- [x] 9.2 Add process-memory capture implementation (Windows) and unsupported-platform stub
- [x] 9.3 Add configurable local file chunk reading for YARA (`-yara-read-chunk`)

## 10. Cloud Provider Configuration & Weighting

- [x] 10.1 Standardize provider config fields for all cloud platforms (`api_key`, `base_url`, `proxy_url`, `rate_limit`, `timeout`, `cache_ttl`)
- [x] 10.2 Add global proxy with provider-level override semantics for cloud requests
- [x] 10.3 Apply provider-aware cloud weighting and high-confidence floor rules (MalwareBazaar/Triage)

## 11. Historical Backfill (This Conversation)

- [x] 11.1 Backfill cloud config discovery order (`EDR_CLOUD_CONFIG` -> `<exe-dir>/edr-cloud.json` -> `./edr-cloud.json` -> `~/.edr/cloud.json`)
- [x] 11.2 Backfill cloud aggregation output fields (`cloud_provider=multi`, `cloud_providers[]`)
- [x] 11.3 Backfill deprecation notes for single-provider selector (`-cloud-provider`, `EDR_CLOUD_PROVIDER`)
- [x] 11.4 Backfill local rules auto-discovery precedence (`-yara-rules` -> `EDR_YARA_RULES` -> `rules/yaraRules|rules`)
- [x] 11.5 Backfill distribution behavior (`dist` includes binary + native libs + rules; `edr-cloud.json` remains external)
- [x] 11.6 Backfill CLI help regression fix (`edr process scan -h` shows full flag list)
- [x] 11.7 Backfill bundled YARA rule sanity fixes (never-match expressions corrected)
