#!/usr/bin/env sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/malt-wasm-vectors.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
sh "$repo_root/scripts/build-verifier-wasm.sh" "$work_dir/verifier"
for backend in all kzg ipa; do
 node "$repo_root/scripts/run-authentication-wasm.mjs" verifier "$work_dir/verifier/malt-verifier.wasm" "$work_dir/verifier/wasm_exec.js" "$repo_root/conformance/authentication-v1.json" "$backend"
done
