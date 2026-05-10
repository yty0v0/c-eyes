## Validation Summary

This file records runtime validation evidence gathered after backend-alignment work was archived.

## Validation Outcome

### 1. Archive / OCI / image-reference regression coverage
Focused regression tests passed after backend isolation and OCI-reference selection alignment:
- `go test ./internal/sbom`
- `go test ./cmd/edr`

These regressions covered:
- filesystem path mode
- image archive mode
- OCI layout mode
- image-reference error diagnostics
- OCI layout reference selection by tag/digest

### 2. Windows Docker native success path
The aligned backend layer was exercised successfully through a real Docker-backed packaged distribution run:

```powershell
.\c-eyes.exe sbom --image example.com/demo:latest -o .\image-success.json
```

The command completed successfully after the offline test image was loaded into the Docker daemon.

### 3. WSL Docker-backed packaged Linux run
In the Administrator user session, the packaged Linux distribution created `image-success.json` via:

```powershell
wsl -e bash -lc "cd /mnt/d/edrsystem/dist-linux-amd64 && ./c-eyes sbom --image example.com/demo:latest -o ./image-success.json"
```

An output file was generated successfully, confirming that the aligned backend layer was able to run through the packaged Linux distribution path in a Docker-integrated WSL environment.

## Remaining Parity Gaps

The backend layer is substantially closer to the reference tool, but the following parity gaps remain:
- Podman success-path runtime verification
- Containerd success-path runtime verification
- Remote-registry success-path verification under stable outbound network access
- Deeper metadata/provenance parity compared to the reference tool's more mature backend implementation

## Conclusion

The aligned backend is now validated beyond unit tests:
- structural parity improvements landed
- key OCI selection behavior was aligned
- Windows Docker success path was verified
- WSL packaged Linux execution path produced successful output

Remaining gaps are focused on additional runtime/backend environments rather than the baseline image-source architecture itself.
