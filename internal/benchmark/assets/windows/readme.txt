Current directory no longer stores the original Windows benchmark script assets.

Windows benchmark now uses:
1. Native Go collectors for system data extraction
2. windows-rules.yaml for baseline evaluation rules
3. Unified benchmark output with readable evidence

Notes:
1. This directory keeps YAML rules and lightweight documentation only.
2. No VBS script or script runtime payload is bundled here anymore.
3. To extend Windows benchmark coverage, add collectors in Go and add rule definitions in YAML.
