#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="$root/.deps/icicle"
expected=aacec3f72f14f53dd96d835698d2c87cde3a68b8
if [[ ! -e "$target" ]]; then
  mkdir -p "$root/.deps"
  git -c core.autocrlf=false clone --depth 1 --branch v2.8.0 https://github.com/ingonyama-zk/icicle.git "$target"
fi
actual="$(git -C "$target" rev-parse HEAD)"
if [[ "$actual" != "$expected" ]]; then
  printf 'ICICLE checkout must be %s; got %s\n' "$expected" "$actual" >&2
  exit 1
fi
printf 'Ready: %s/icicle/include\n' "$target"
