#!/usr/bin/env sh
set -eu

# Use POSIX tools so the gate does not depend on ripgrep in the CI image.
for required in go grep; do
  if ! command -v "$required" >/dev/null 2>&1; then
    printf '%s\n' "required command not found: $required" >&2
    exit 127
  fi
done

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/malt-writer-backends.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

check_backend_dependencies() {
  backend="$1"
  tags="$2"
  excluded="$3"
  # Keep dependency queries outside conditions/pipelines: any go list failure
  # must stop the gate, including one after partial dependency output.
  (cd "$repo_root" && go list -buildvcs=false -deps -tags="$tags" ./cmd/malt-writer-wasm) > "$work_dir/$backend-native-deps"
  (cd "$repo_root" && GOOS=js GOARCH=wasm go list -buildvcs=false -deps -tags="$tags" ./cmd/malt-writer-wasm) > "$work_dir/$backend-wasm-deps"
  if grep -F -x "github.com/dewebprotocol/malt-core/auth/commitment/$excluded" "$work_dir/$backend-native-deps" "$work_dir/$backend-wasm-deps" >/dev/null; then
    printf '%s\n' "$backend writer unexpectedly links the $excluded backend" >&2
    exit 1
  else
    status=$?
    # Only status 1 means no match. Missing/broken tools and input errors must
    # never be interpreted as proof of backend isolation.
    if [ "$status" -ne 1 ]; then
      printf '%s\n' "$backend writer dependency matching failed (grep exit $status)" >&2
      exit "$status"
    fi
  fi
  printf '%s\n' "$backend writer: native and js/wasm dependencies exclude $excluded"
}

check_backend_dependencies kzg writer_kzg ipa
check_backend_dependencies ipa writer_ipa,malt_no_default_kzg kzg
