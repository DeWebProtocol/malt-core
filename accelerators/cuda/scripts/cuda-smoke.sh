#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
include="$root/.deps/icicle/icicle/include"
if [[ ! -d "$include" ]]; then
  printf 'Run bash scripts/prepare-icicle.sh first.\n' >&2
  exit 1
fi
if command -v cygpath >/dev/null 2>&1; then
  include="$(cygpath -am "$include")"
fi
cd "$root"
export GOWORK=off
export CGO_ENABLED=0
go run ./cmd/cuda-smoke --icicle-include "$include" "$@"
