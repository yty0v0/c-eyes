## 1. Risk Streaming Output Contract

- [x] 1.1 Verify `risk-analysis` spec delta covers incremental risky-target streaming for standalone and chained modes.
- [x] 1.2 Verify severity-band color behavior and plain-text fallback are explicitly testable in scenarios.
- [x] 1.3 Verify completion summary contract (total + non-zero severity buckets) is documented.
- [x] 1.4 Verify single-row risk progress stability requirement is documented with long-line terminal scenario.

## 2. Filescan Permission Feedback Contract

- [x] 2.1 Verify `filescan` spec delta documents explicit access-denied failure for unreadable path roots.
- [x] 2.2 Verify `filescan` spec delta documents per-inaccessible-entry warnings without aborting full run.
- [x] 2.3 Verify `filescan` spec delta documents no synthetic child warnings under denied directories.

## 3. Local File Collection Permission Semantics

- [x] 3.1 Verify `file-scan` spec delta documents path-mode directory readability pre-check semantics.
- [x] 3.2 Verify `file-scan` spec delta documents callback stage and per-entry error surfacing requirements.

## 4. Project Whitelist Baseline Policy Contract

- [x] 4.1 Verify `risk-whitelist-policy` spec delta documents default-on baseline integration behavior.
- [x] 4.2 Verify explicit environment override scenarios (disable, explicit-enable failure path, override/noise behavior) are documented.
- [x] 4.3 Verify baseline include semantics for `c-eyes`/`c-eyes.exe` artifacts are documented.

## 5. Validation and Handoff

- [x] 5.1 Run OpenSpec validation for the new change and resolve formatting/schema issues.
- [x] 5.2 Summarize this change scope and reference paths for implementation/archive follow-up.
