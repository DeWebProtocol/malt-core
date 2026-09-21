#!/usr/bin/env sh
set -eu

output_dir=${1:-dist/writer}
mkdir -p "$output_dir"
GOOS=js GOARCH=wasm go build -p=6 -buildvcs=false -trimpath -tags=writer_kzg \
  -o "$output_dir/malt-writer-kzg.wasm" ./cmd/malt-writer-wasm
for profile in direct compact fast; do
  GOOS=js GOARCH=wasm go build -p=6 -buildvcs=false -trimpath \
    -tags=writer_ipa,malt_no_default_kzg \
    -ldflags="-X=main.ipaCommitterProfile=$profile" \
    -o "$output_dir/malt-writer-ipa-$profile.wasm" ./cmd/malt-writer-wasm
done
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$output_dir/wasm_exec.js"
cp cmd/malt-writer-wasm/browser/malt-writer-worker.mjs "$output_dir/malt-writer-worker.mjs"
cp cmd/malt-writer-wasm/browser/malt-writer-workers.mjs "$output_dir/malt-writer-workers.mjs"
printf '%s\n' \
  "built $output_dir/malt-writer-kzg.wasm" \
  "built $output_dir/malt-writer-ipa-direct.wasm" \
  "built $output_dir/malt-writer-ipa-compact.wasm" \
  "built $output_dir/malt-writer-ipa-fast.wasm" \
  "built $output_dir/malt-writer-worker.mjs" \
  "built $output_dir/malt-writer-workers.mjs"
