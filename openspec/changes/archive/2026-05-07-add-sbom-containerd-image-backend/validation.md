## Validation Summary

This file records post-implementation runtime validation evidence gathered after the change was archived.

## What Was Verified

### 1. Windows Docker native backend success path
- Docker Desktop was installed successfully on the Windows host.
- Docker daemon service was started and the local test image `example.com/demo:latest` was loaded into the daemon from an offline image tar.
- The following command succeeded in the packaged Windows distribution:

```powershell
.\c-eyes.exe sbom --image example.com/demo:latest -o .\image-success.json
```

- The generated `image-success.json` contained SBOM document structure and package data for the test image.

### 2. WSL Docker socket availability
- In the Administrator user session, WSL reported an available Docker socket:

```powershell
wsl -e bash -lc "test -S /var/run/docker.sock && echo DOCKER_SOCK_OK || echo DOCKER_SOCK_MISSING"
```

- Result: `DOCKER_SOCK_OK`

### 3. WSL packaged Linux distribution command success evidence
- In the Administrator user session, the packaged Linux binary successfully generated `image-success.json` through:

```powershell
wsl -e bash -lc "cd /mnt/d/edrsystem/dist-linux-amd64 && rm -f image-success.json && ./c-eyes sbom --image example.com/demo:latest -o ./image-success.json && ls -l image-success.json"
```

- Result: `image-success.json` was created successfully.

## What Remains Unverified

The following native image success paths were not fully validated end-to-end in this environment:
- Podman native backend success path
- Containerd native backend success path
- Remote registry success path under stable outbound network access

## Interpretation

At this point, the image-reference SBOM path is no longer only theoretically implemented:
- Windows + Docker native success path is verified
- WSL Docker socket availability is verified
- Packaged Linux binary `--image` command execution successfully produced an output artifact in WSL

Remaining validation gaps are now runtime-environment specific rather than implementation-blocking.
