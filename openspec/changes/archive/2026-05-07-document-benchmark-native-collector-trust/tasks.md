## 1. Native-Only Contract

- [x] 1.1 Remove remaining command/script-based benchmark fact collection from the four benchmark templates and keep Go-native collection paths for `windows`, `linux`, `euleros`, and `kylin`.
- [x] 1.2 Ensure all four supported baseline levels continue to resolve through the same native-only collector contract instead of template-specific command fallbacks.
- [x] 1.3 Keep benchmark rule evaluation on YAML metadata only, without reintroducing vendor benchmark script replay into runtime collection.

## 2. Windows Native Trustworthiness

- [x] 2.1 Refine Windows security-policy collection so system-access, event-audit, and privilege-rights sections load independently instead of failing as one bundle.
- [x] 2.2 Fix Windows native password-policy collection to use a trustworthy SAM / LSA / NetAPI access path and return determinate values for fields such as `PasswordComplexity`, `AllowAdministratorLockout`, and `ClearTextPassword`.
- [x] 2.3 Keep `unknown` as the only allowed outcome when no sufficiently trustworthy native source exists, without introducing command-based value backfill.

## 3. Validation and Spec Recording

- [x] 3.1 Add or use live native benchmark validation to compare Windows native security-policy results against effective platform truth sources.
- [x] 3.2 Re-run benchmark validation across the four template families or their highest-coverage available environments, including all supported baseline levels where applicable.
- [x] 3.3 Record the native-only and trustworthiness requirements in OpenSpec `benchmark-scan` delta docs so future maintenance cannot regress to command collection or low-trust `unknown` results.

### Session Notes

- 2026-05-06: Added Linux-family live parity validation entry points in `internal/benchmark/unix_native_parity_live_test.go`.
- 2026-05-06: Verified Linux and EulerOS-compatible rule fields on Ubuntu 24.04 WSL2 root environment with local Linux Go 1.25.0 toolchain.
- 2026-05-06: Kylin-specific live execution remains pending matching host availability.
- 2026-05-07: Synced the benchmark native-only implementation into the `c-eyes` source tree and removed legacy benchmark command/powershell collector leftovers there.
- 2026-05-07: Rebuilt the four distribution directories from the updated implementation: `dist-windows-amd64`, `dist-windows-amd64-public`, `dist-linux-amd64`, and `dist-linux-amd64-public`.
