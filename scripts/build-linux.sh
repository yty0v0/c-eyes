#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-dist-linux-amd64}"
OFFLINE="${OFFLINE:-1}"
LINK_MODE="${LINK_MODE:-static}"
COPY_RULES="${COPY_RULES:-0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YARA_BASE="$ROOT/third_party/yara-x-dist-linux"
if [[ ! -d "$YARA_BASE/include" || ! -d "$YARA_BASE/lib" ]]; then
  YARA_BASE="$ROOT/third_party/yara-x-dist"
fi
GO_TOOLCHAIN_ROOT="${GO_TOOLCHAIN_ROOT:-$ROOT/tmp/go-toolchain-local}"

version_ge() {
  local current="$1"
  local required="$2"
  [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n 1)" == "$required" ]]
}

detect_go_version() {
  local raw
  raw="$(go version 2>/dev/null || true)"
  if [[ -z "$raw" ]]; then
    echo ""
    return
  fi
  echo "$raw" | awk '{print $3}' | sed 's/^go//'
}

setup_offline_go() {
  if [[ "$OFFLINE" != "1" ]]; then
    return
  fi

  local required_go toolchain_tag toolchain_dir toolchain_zip go_ver
  required_go="$(awk '/^go / { print $2; exit }' "$ROOT/go.mod")"
  toolchain_tag="v0.0.1-go${required_go}.linux-amd64"
  toolchain_dir="$GO_TOOLCHAIN_ROOT/golang.org/toolchain@${toolchain_tag}"
  toolchain_zip="$ROOT/tmp/${toolchain_tag}.zip"

  export GOTOOLCHAIN=local
  export GOPROXY="${GOPROXY:-off}"
  export GOSUMDB="${GOSUMDB:-off}"

  if [[ -d "$toolchain_dir/bin" ]]; then
    export PATH="$toolchain_dir/bin:$PATH"
  elif [[ -f "$toolchain_zip" ]]; then
    if ! command -v unzip >/dev/null 2>&1; then
      echo "unzip is required to expand offline Go toolchain: $toolchain_zip" >&2
      exit 1
    fi
    mkdir -p "$GO_TOOLCHAIN_ROOT"
    unzip -qo "$toolchain_zip" -d "$GO_TOOLCHAIN_ROOT"
    if [[ -d "$toolchain_dir/bin" ]]; then
      export PATH="$toolchain_dir/bin:$PATH"
    fi
  fi

  if [[ -z "${GOMODCACHE:-}" ]]; then
    local cache_candidates=(
      "$ROOT/tmp/go-mod-cache"
      "/mnt/c/Users/Administrator/go/pkg/mod"
      "$HOME/go/pkg/mod"
    )
    local c
    for c in "${cache_candidates[@]}"; do
      if [[ -d "$c" ]] && [[ -n "$(ls -A "$c" 2>/dev/null)" ]]; then
        export GOMODCACHE="$c"
        break
      fi
    done
  fi

  go_ver="$(detect_go_version)"
  if [[ -z "$go_ver" ]]; then
    echo "go not found in PATH (offline mode)." >&2
    exit 1
  fi
  if ! version_ge "$go_ver" "$required_go"; then
    echo "offline mode requires go >= $required_go, found $go_ver." >&2
    echo "Provide local toolchain in: $toolchain_dir" >&2
    echo "Or place zip at: $toolchain_zip" >&2
    exit 1
  fi

  echo "Offline mode: ON"
  echo "Go: $(go version)"
  if [[ -n "${GOMODCACHE:-}" ]]; then
    echo "GOMODCACHE: $GOMODCACHE"
  fi
}

has_linux_so() {
  local lib_dir="$1"
  [[ -f "$lib_dir/libyara_x_capi.so" || -f "$lib_dir/libyara_x_capi.so.0" || -f "$lib_dir/libyara_x_capi.so.1" || -f "$lib_dir/libyara_x_capi.so.1.14.0" ]]
}

resolve_linux_lib_dir() {
  local base="$1"
  local lib_root="$base/lib"
  local multiarch="$lib_root/x86_64-linux-gnu"
  if [[ -d "$multiarch" ]]; then
    if has_linux_so "$multiarch"; then
      echo "$multiarch"
      return
    fi
    if ! has_linux_so "$lib_root"; then
      echo "$multiarch"
      return
    fi
  fi
  echo "$lib_root"
}

INCLUDE="$YARA_BASE/include"
LIB="$(resolve_linux_lib_dir "$YARA_BASE")"

if [[ ! -d "$INCLUDE" || ! -d "$LIB" ]]; then
  echo "linux yara dist not found. Expected one of: $ROOT/third_party/yara-x-dist-linux or $ROOT/third_party/yara-x-dist" >&2
  exit 1
fi

if ! has_linux_so "$LIB"; then
  if [[ ! -d "$ROOT/third_party/yara-x-src" ]]; then
    echo "yara-x-src not found. Clone YARA-X into third_party/yara-x-src first." >&2
    exit 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required to build yara-x-capi (Rust toolchain)." >&2
    exit 1
  fi
  if ! cargo cinstall -h >/dev/null 2>&1; then
    echo "cargo-c is required. Install with: cargo install cargo-c" >&2
    exit 1
  fi
  (cd "$ROOT/third_party/yara-x-src" && cargo cinstall -p yara-x-capi --release --prefix "$YARA_BASE")
fi

if ! command -v pkg-config >/dev/null 2>&1; then
  echo "pkg-config is required for cgo build on Linux." >&2
  exit 1
fi

setup_offline_go

export PKG_CONFIG_PATH="$LIB/pkgconfig:${PKG_CONFIG_PATH:-}"
export CGO_ENABLED=1
export CGO_CFLAGS="-I$INCLUDE"

if [[ "$LINK_MODE" == "static" ]]; then
  STATIC_ARCHIVE="$LIB/libyara_x_capi.a"
  if [[ ! -f "$STATIC_ARCHIVE" ]]; then
    echo "static archive not found: $STATIC_ARCHIVE" >&2
    exit 1
  fi
  # Keep glibc/system runtime dynamic, but link yara_x_capi itself statically
  # so distribution no longer requires libyara_x_capi.so files.
  export CGO_LDFLAGS="$STATIC_ARCHIVE -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc"
else
  export CGO_LDFLAGS="-L$LIB -lyara_x_capi -Wl,-rpath,\$ORIGIN"
fi

OUT_DIR="$ROOT/$OUTPUT_DIR"
mkdir -p "$OUT_DIR"

EXE="$OUT_DIR/c-eyes"
(
  cd "$ROOT"
  go build -tags yarax -o "$EXE" ./cmd/edr
)

if [[ "$LINK_MODE" == "static" ]]; then
  rm -f "$OUT_DIR/libyara_x_capi.so"*
else
  shopt -s nullglob
  so_files=("$LIB/libyara_x_capi.so"*)
  if [[ ${#so_files[@]} -gt 0 ]]; then
    rm -f "$OUT_DIR/libyara_x_capi.so"*
    # Use -L to materialize symlinks as real files for portable distribution archives (zip/scp).
    cp -L "${so_files[@]}" "$OUT_DIR/"
  else
    echo "warning: libyara_x_capi.so not found under $LIB" >&2
  fi
  shopt -u nullglob
fi

if [[ "$COPY_RULES" == "1" ]]; then
  RULES_SRC="$ROOT/rules/yaraRules"
  if [[ -d "$RULES_SRC" ]]; then
    RULES_DEST="$OUT_DIR/rules/yaraRules"
    mkdir -p "$RULES_DEST"
    cp -a "$RULES_SRC/." "$RULES_DEST/"
    echo "Copied rules: $RULES_DEST"
  else
    echo "Rules not found at $RULES_SRC. Skipping rule copy."
  fi
else
  rm -rf "$OUT_DIR/rules"
  echo "Rules copy disabled (using embedded rules by default)."
fi

CLOUD_CFG_SRC="$ROOT/c-eyes-cloud.example.json"
if [[ -f "$CLOUD_CFG_SRC" ]]; then
  cp -a "$CLOUD_CFG_SRC" "$OUT_DIR/c-eyes-cloud.json"
  echo "Copied: c-eyes-cloud.json (API key template)"
else
  echo "Cloud config template not found at $CLOUD_CFG_SRC. Skipping config copy."
fi

echo "Built: $EXE"
if [[ "$LINK_MODE" == "static" ]]; then
  echo "Linked: libyara_x_capi.a (static)"
else
  echo "Copied: libyara_x_capi.so*"
fi
echo "Link mode: $LINK_MODE"
