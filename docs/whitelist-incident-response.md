# Whitelist Incident Response Guide

## 1. Certificate Leak / Theft Emergency

Trigger examples:
- vendor public disclosure of stolen signing certificate
- CTI confirms abused certificate in the wild

Immediate actions:
1. Add certificate thumbprint/serial/issuer to `revoked_certificates`.
2. Publish updated whitelist policy to all endpoints.
3. Force policy reload or restart EDR service.
4. Run targeted risk re-analysis for recent signed binaries.

Post-incident:
- add retrospective hunting query by certificate metadata
- verify no allow decisions were granted after policy update timestamp

## 2. BYOVD Emergency Blocking

Trigger examples:
- vulnerable driver exploited for privilege escalation
- new entry in Microsoft Vulnerable Driver Blocklist

Immediate actions:
1. Add driver hash/name/path indicators to `vulnerable_drivers`.
2. Promote to deny-first policy (no grace period).
3. Re-scan running processes and loaded drivers on critical hosts.

Post-incident:
- tune blocklist for false positives (publisher/version constraints if needed)
- maintain rollback snapshot for emergency recovery

## 3. LOLBin Abuse Detection

When unexpected PowerShell/CMD/WMIC/CERTUTIL activity appears:
1. Confirm command line not in approved LOLBin command rules.
2. Keep rule as `continue` to force YARA + cloud analysis.
3. Only add command whitelists for deterministic, auditable automation workflows.

