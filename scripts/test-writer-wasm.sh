#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sh "$repo_root/scripts/check-writer-backends.sh"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/malt-writer-wasm.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

node --test \
  "$repo_root/cmd/malt-writer-wasm/browser/malt-writer-workers.test.mjs"

sh "$repo_root/scripts/build-writer-wasm.sh" "$work_dir/writer"
node "$repo_root/scripts/run-writer-wasm-smoke.mjs" \
  "$work_dir/writer/malt-writer-kzg.wasm" \
  "$work_dir/writer/wasm_exec.js" \
  "$repo_root/conformance/client-root/v4/vectors.json" \
  kzg
node "$repo_root/scripts/run-authentication-wasm.mjs" writer \
  "$work_dir/writer/malt-writer-kzg.wasm" "$work_dir/writer/wasm_exec.js" \
  "$repo_root/conformance/authentication-v0.json" kzg
node "$repo_root/scripts/run-retained-writer-wasm.mjs" \
  "$work_dir/writer/malt-writer-kzg.wasm" "$work_dir/writer/wasm_exec.js" kzg
for profile in direct compact fast; do
  node "$repo_root/scripts/run-writer-wasm-smoke.mjs" \
    "$work_dir/writer/malt-writer-ipa-$profile.wasm" \
    "$work_dir/writer/wasm_exec.js" \
    "$repo_root/conformance/client-root/v4/vectors.json" \
    ipa "$profile"
  node "$repo_root/scripts/run-authentication-wasm.mjs" writer \
    "$work_dir/writer/malt-writer-ipa-$profile.wasm" "$work_dir/writer/wasm_exec.js" \
    "$repo_root/conformance/authentication-v0.json" ipa
  node "$repo_root/scripts/run-retained-writer-wasm.mjs" \
    "$work_dir/writer/malt-writer-ipa-$profile.wasm" "$work_dir/writer/wasm_exec.js" ipa "$profile"
done
node "$repo_root/scripts/run-writer-worker-smoke.mjs" \
  "$work_dir/writer/malt-writer-ipa-compact.wasm" \
  "$work_dir/writer/wasm_exec.js" \
  "$work_dir/writer/malt-writer-workers.mjs" \
  "$work_dir/writer/malt-writer-worker.mjs" \
  "$repo_root/conformance/client-root/v4/vectors.json" \
  ipa compact
