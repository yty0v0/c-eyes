## 1. Policy Model and Configuration

- [x] 1.1 Define whitelist decision models (`allow/deny/continue`) and audit fields in `internal/riskanalysis/types.go`
- [x] 1.2 Add whitelist policy loader for trusted publishers, revoked certificates, BYOVD list, and LOLBin command-line rules
- [x] 1.3 Add validation and version metadata checks for policy files (fail-safe defaults)

## 2. Hash & Reputation Infrastructure

- [x] 2.1 Implement authority hash repository adapters (NSRL + enterprise baseline)
- [x] 2.2 Implement local reputation safe/malicious cache with TTL and LRU bounds
- [x] 2.3 Add fast lookup helper APIs for cache/hash hit path in risk analyzer

## 3. Whitelist Engine Core

- [x] 3.1 Implement `WhitelistEngine.Evaluate` with precedence `deny > allow > continue`
- [x] 3.2 Implement trusted publisher matching (publisher + product + signature validity)
- [x] 3.3 Implement certificate denylist matching (thumbprint/serial/issuer)
- [x] 3.4 Implement BYOVD deny matching (hash/driver identity)
- [x] 3.5 Implement path-context rules (`System32+Microsoft`, business path + parent context)
- [x] 3.6 Implement LOLBin command-line whitelist matching and non-match continuation

## 4. Analyzer Integration (Best-Fit with Current Code)

- [x] 4.1 Inject whitelist gate before local/cloud stages in `Analyzer.executeSmart`
- [x] 4.2 Reuse whitelist gate in `Analyzer.executeDeep` pre-check and short-circuit logic
- [x] 4.3 Add cache/hash pre-check in `fast` stage before MB/VT query
- [x] 4.4 Ensure deny verdict maps to high-risk final score and allow verdict maps to safe score with evidence

## 5. Record Enrichment and Output

- [x] 5.1 Enrich file risk records with signer subject and certificate thumbprint from file scan results
- [x] 5.2 Enrich process risk records with command line and parent context fields for LOLBin policies
- [x] 5.3 Add `whitelist_analysis` section to JSON output and Excel columns for whitelist decision/audit
- [x] 5.4 Keep progress output on stderr only, preserving valid JSON on stdout

## 6. Testing and Verification

- [x] 6.1 Add unit tests for whitelist precedence and each policy dimension
- [x] 6.2 Add analyzer tests for allow/deny/continue short-circuit behavior in `smart/deep`
- [x] 6.3 Add tests for VT token bucket degrade path and no-block behavior
- [x] 6.4 Add integration tests covering funnel order: cache -> authority hash -> signature -> YARA -> cloud

## 7. Documentation and Operations

- [x] 7.1 Update `docs/usage.md` with whitelist policy files, precedence, and examples
- [x] 7.2 Add operations guide for NSRL/enterprise baseline import and refresh cadence
- [x] 7.3 Add incident-response guidance for certificate leak and BYOVD emergency block updates

## 8. CLI Alignment from Ongoing Conversation

- [x] 8.1 Remove legacy risk flags `-local`, `-cloud`, and `-cloud-provider`; keep `-mode` as the single mode entry
- [x] 8.2 Make `-dir` imply recursive traversal by default and remove `-r` from risk-analysis CLI surface
- [x] 8.3 Localize root/process/file/risk `-h/--help` output to Chinese
- [x] 8.4 Add/adjust tests for legacy flag rejection (`-local`, `-cloud-provider`, `-r`) and direct `-dir` acceptance

## 9. Severity Scoring Robustness from Ongoing Conversation

- [x] 9.1 Add fallback severity mapping for local YARA matches when metadata `severity` is missing, invalid, or `<= 0`
- [x] 9.2 Integrate fallback assignment into YARA-X match conversion so high-risk families do not collapse into `0` local score
- [x] 9.3 Add unit tests covering known family fallback, unmatched-rule default fallback, and empty-signal zero behavior

