#!/usr/bin/env sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sh "$repo_root/scripts/check-writer-backends.sh"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/malt-writer-wasm.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
node --test "$repo_root/cmd/malt-writer-wasm/browser/malt-writer-workers.test.mjs"
sh "$repo_root/scripts/build-writer-wasm.sh" "$work_dir/writer"
for target in kzg direct compact fast; do
  backend=ipa
  profile=$target
  wasm="$work_dir/writer/malt-writer-ipa-$profile.wasm"
  if [ "$target" = kzg ]; then backend=kzg; profile=; wasm="$work_dir/writer/malt-writer-kzg.wasm"; fi
  node "$repo_root/scripts/run-authentication-wasm.mjs" writer "$wasm" "$work_dir/writer/wasm_exec.js" "$repo_root/conformance/authentication-v1.json" "$backend"
  node "$repo_root/scripts/run-retained-writer-wasm.mjs" "$wasm" "$work_dir/writer/wasm_exec.js" "$backend" "$profile"
  node "$repo_root/scripts/run-authentication-batch-wasm.mjs" "$wasm" "$work_dir/writer/wasm_exec.js" "$backend" "$profile"
done
node "$repo_root/scripts/run-writer-worker-smoke.mjs" "$work_dir/writer/malt-writer-ipa-compact.wasm" "$work_dir/writer/wasm_exec.js" "$work_dir/writer/malt-writer-workers.mjs" "$work_dir/writer/malt-writer-worker.mjs" ipa compact
