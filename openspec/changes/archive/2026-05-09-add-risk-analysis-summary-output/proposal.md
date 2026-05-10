## Why

Risk analysis currently streams risky findings and exports detailed per-record results, but it does not provide a unified benchmark-style summary contract across JSON, terminal, and Excel outputs. We need a structured summary now so operators can quickly understand risky totals and special unresolved states without manually aggregating result records.

## What Changes

- Add benchmark-style `summary` output to risk analysis results.
- Cover all currently supported risk-analysis entry paths:
  - standalone `c-eyes -r`
  - chained `c-eyes hostscan ... -r`
  - chained `c-eyes filescan ... -r`
- Extend terminal, JSON, and Excel risk outputs with consistent summary semantics.
- Exclude `无风险` from summary reporting.
- Include explicit counts for:
  - `高危`
  - `高风险`
  - `中风险`
  - `低风险`
  - `分析中`
  - `可疑-需本地核实`
  - total summarized results
- **BREAKING** Change risk JSON top-level output from bare result array to an object containing `summary` and `results`.

## Capabilities

### New Capabilities
- `risk-analysis-summary`: Provide normalized summary aggregation for risk analysis outputs across terminal, JSON, and Excel destinations.

### Modified Capabilities
- `risk-analysis`: Extend risk analysis output contract to include structured summary aggregation and destination-specific rendering rules.
- `global-output`: Support benchmark-style summary object/sheet behavior for risk-analysis exports in addition to existing row output handling.

## Impact

- Affected code:
  - `cmd/edr` risk output shaping, terminal summary rendering, JSON serialization, and Excel export
  - `internal/riskanalysis` summary aggregation model and level classification helpers
  - output helpers shared by benchmark/global-output flows
- Affected behavior:
  - risk JSON output becomes `{ summary, results }`
  - risk Excel export gains summary sheet
  - risk terminal output ends with a complete categorized summary instead of only non-zero severity-band summary
- Compatibility:
  - consumers expecting bare JSON arrays will need to adapt to the new object wrapper
