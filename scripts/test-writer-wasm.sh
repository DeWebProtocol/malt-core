#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/malt-writer-wasm.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

node --test \
  "$repo_root/cmd/malt-writer-wasm/browser/malt-writer-workers.test.mjs"

if go list -buildvcs=false -deps -tags=writer_kzg ./cmd/malt-writer-wasm | rg -q '/auth/commitment/ipa$'; then
  printf '%s\n' "KZG writer unexpectedly links the IPA backend" >&2
  exit 1
fi
if go list -buildvcs=false -deps -tags=writer_ipa,malt_no_default_kzg ./cmd/malt-writer-wasm | rg -q '/auth/commitment/kzg$'; then
  printf '%s\n' "IPA writer unexpectedly links the KZG backend" >&2
  exit 1
fi

sh "$repo_root/scripts/build-writer-wasm.sh" "$work_dir/writer"
node "$repo_root/scripts/run-writer-wasm-smoke.mjs" \
  "$work_dir/writer/malt-writer-kzg.wasm" \
  "$work_dir/writer/wasm_exec.js" \
  "$repo_root/conformance/client-root/v1/vectors.json" \
  kzg
for profile in direct compact fast; do
  node "$repo_root/scripts/run-writer-wasm-smoke.mjs" \
    "$work_dir/writer/malt-writer-ipa-$profile.wasm" \
    "$work_dir/writer/wasm_exec.js" \
    "$repo_root/conformance/client-root/v1/vectors.json" \
    ipa "$profile"
done
node "$repo_root/scripts/run-writer-worker-smoke.mjs" \
  "$work_dir/writer/malt-writer-ipa-compact.wasm" \
  "$work_dir/writer/wasm_exec.js" \
  "$work_dir/writer/malt-writer-workers.mjs" \
  "$work_dir/writer/malt-writer-worker.mjs" \
  "$repo_root/conformance/client-root/v1/vectors.json" \
  ipa compact
