# Whitelist Operations Guide

## 1. Data Sources

- NSRL authority hashes: imported from approved NSRL export files.
- Enterprise baseline hashes: imported from golden image / internal software release pipeline.
- Local reputation cache: auto-generated runtime cache for recently validated safe/malicious hashes.

## 2. Refresh Cadence

- NSRL: weekly full refresh (or at least monthly when offline environments apply).
- Enterprise baseline: per release + daily incremental sync.
- Certificate denylist / BYOVD: immediate out-of-band update on threat intel notice.

## 3. Import Format

Whitelist policy supports:
- inline arrays (`nsrl_hashes`, `enterprise_hashes`)
- external files (`nsrl_hash_files`, `enterprise_hash_files`)

File parser accepts:
- plain text (`<sha256>` each line)
- CSV/TSV (first column treated as hash)
- comment lines starting with `#`

## 4. Validation Checklist

Before rollout:
- hash count and duplicate rate are within expected range
- all hash entries are SHA-256 (64 hex chars)
- policy `version` is set
- LOLBin command rules only use `exact|prefix|contains`

## 5. Rollout Strategy

1. Stage in monitor mode (collect whitelist decisions and evidence).
2. Verify false-allow and false-deny rates with SOC review.
3. Enable enforcement for deny rules first (revoked cert + BYOVD).
4. Gradually enable allow rules for trusted publisher and business path context.

