#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/malt-writer-wasm.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

node --test \
  "$repo_root/cmd/malt-writer-wasm/browser/malt-writer-workers.test.mjs"

# Check both native test builds and the actual js/wasm target. Keep go list
# outside the pipeline so a failed dependency query cannot look like isolation.
check_backend_dependencies() {
  backend="$1"
  tags="$2"
  excluded="$3"
  (cd "$repo_root" && go list -buildvcs=false -deps -tags="$tags" ./cmd/malt-writer-wasm) > "$work_dir/$backend-native-deps"
  (cd "$repo_root" && GOOS=js GOARCH=wasm go list -buildvcs=false -deps -tags="$tags" ./cmd/malt-writer-wasm) > "$work_dir/$backend-wasm-deps"
  if rg -q "/auth/commitment/$excluded$" "$work_dir/$backend-native-deps" "$work_dir/$backend-wasm-deps"; then
    printf '%s\n' "$backend writer unexpectedly links the $excluded backend" >&2
    exit 1
  fi
}
check_backend_dependencies kzg writer_kzg ipa
check_backend_dependencies ipa writer_ipa,malt_no_default_kzg kzg

sh "$repo_root/scripts/build-writer-wasm.sh" "$work_dir/writer"
node "$repo_root/scripts/run-writer-wasm-smoke.mjs" \
  "$work_dir/writer/malt-writer-kzg.wasm" \
  "$work_dir/writer/wasm_exec.js" \
  "$repo_root/conformance/client-root/v2/vectors.json" \
  kzg
node "$repo_root/scripts/run-authentication-wasm.mjs" writer \
  "$work_dir/writer/malt-writer-kzg.wasm" "$work_dir/writer/wasm_exec.js" \
  "$repo_root/conformance/authentication-v0.json" kzg
for profile in direct compact fast; do
  node "$repo_root/scripts/run-writer-wasm-smoke.mjs" \
    "$work_dir/writer/malt-writer-ipa-$profile.wasm" \
    "$work_dir/writer/wasm_exec.js" \
    "$repo_root/conformance/client-root/v2/vectors.json" \
    ipa "$profile"
  node "$repo_root/scripts/run-authentication-wasm.mjs" writer \
    "$work_dir/writer/malt-writer-ipa-$profile.wasm" "$work_dir/writer/wasm_exec.js" \
    "$repo_root/conformance/authentication-v0.json" ipa
done
node "$repo_root/scripts/run-writer-worker-smoke.mjs" \
  "$work_dir/writer/malt-writer-ipa-compact.wasm" \
  "$work_dir/writer/wasm_exec.js" \
  "$work_dir/writer/malt-writer-workers.mjs" \
  "$work_dir/writer/malt-writer-worker.mjs" \
  "$repo_root/conformance/client-root/v2/vectors.json" \
  ipa compact
