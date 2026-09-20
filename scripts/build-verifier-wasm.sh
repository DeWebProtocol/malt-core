#!/usr/bin/env sh
set -eu

output_dir=${1:-dist/verifier}
mkdir -p "$output_dir"
GOOS=js GOARCH=wasm go build -p=6 -buildvcs=false -trimpath -o "$output_dir/malt-verifier.wasm" ./cmd/malt-verifier-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$output_dir/wasm_exec.js"
printf '%s\n' "built $output_dir/malt-verifier.wasm"
