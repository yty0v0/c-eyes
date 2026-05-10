## 1. Backend Integration

- [x] 1.1 Add a native containerd backend branch to `sbom --image` backend resolution without changing the public CLI
- [x] 1.2 Implement environment-aware containerd socket/namespace discovery and explicit backend error reporting
- [x] 1.3 Export containerd-resolved images through native APIs and reuse the existing merged-rootfs extraction pipeline

## 2. Regression Protection

- [x] 2.1 Add targeted tests for containerd backend selection or failure diagnostics without regressing Docker/Podman/remote behavior
- [x] 2.2 Re-run focused SBOM and CLI regressions to ensure archive/OCI/path/image modes remain stable

## 3. Verification

- [x] 3.1 Run `openspec validate --strict --no-interactive add-sbom-containerd-image-backend`
- [x] 3.2 Prepare implementation notes on remaining environment limits, if containerd success-path execution cannot be exercised locally
