#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_version="${1:?usage: scripts/build-wasm-release.sh vX.Y.Z[-prerelease] [output-directory]}"
output_dir="${2:-${repo_root}/dist/wasm-release}"

if [[ ! "${release_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
	printf 'invalid MALT release version: %s\n' "${release_version}" >&2
	exit 1
fi

for command_name in awk env find git go gzip install mktemp node sha256sum tar; do
	command -v "${command_name}" >/dev/null 2>&1 || {
		printf 'required command not found: %s\n' "${command_name}" >&2
		exit 1
	}
done

if [[ -n "$(git -C "${repo_root}" status --porcelain --untracked-files=all)" ]]; then
	printf 'MALT source must be clean before constructing release assets\n' >&2
	exit 1
fi

source_commit="$(git -C "${repo_root}" rev-parse HEAD)"
source_epoch="$(git -C "${repo_root}" show -s --format=%ct HEAD)"
if [[ ! "${source_commit}" =~ ^[0-9a-f]{40}$ || ! "${source_epoch}" =~ ^[0-9]+$ ]]; then
	printf 'unable to resolve exact MALT release source\n' >&2
	exit 1
fi
if git -C "${repo_root}" show-ref --verify --quiet "refs/tags/${release_version}"; then
	tagged_commit="$(git -C "${repo_root}" rev-parse "${release_version}^{commit}")"
	if [[ "${tagged_commit}" != "${source_commit}" ]]; then
		printf 'release tag %s points to %s, not HEAD %s\n' \
			"${release_version}" "${tagged_commit}" "${source_commit}" >&2
		exit 1
	fi
fi

mkdir -p "${output_dir}"
if [[ -n "$(find "${output_dir}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	printf 'release output directory must be empty: %s\n' "${output_dir}" >&2
	exit 1
fi

temporary="$(mktemp -d "${TMPDIR:-/tmp}/malt-wasm-release.XXXXXXXX")"
cleanup() {
	if [[ "${temporary}" == "${TMPDIR:-/tmp}"/malt-wasm-release.* && -d "${temporary}" ]]; then
		rm -rf -- "${temporary}"
	fi
}
trap cleanup EXIT

build_source="${temporary}/source"
verifier_staging="${temporary}/verifier"
writer_staging="${temporary}/writer"
release_root="${temporary}/release"
mkdir -p "${build_source}" "${verifier_staging}" "${writer_staging}" "${release_root}"
git -C "${repo_root}" archive --format=tar "${source_commit}" | tar -x -C "${build_source}"

go_directive="$(awk '$1 == "go" { print $2; exit }' "${build_source}/go.mod")"
if [[ ! "${go_directive}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	printf 'go.mod must pin an exact release toolchain version\n' >&2
	exit 1
fi
required_toolchain="go${go_directive}"
go_root="$(
	cd "${build_source}"
	env -u GOROOT -u GOOS -u GOARCH GO111MODULE=on GOENV=off GOWORK=off GOFLAGS= \
		GOTOOLCHAIN="${required_toolchain}" GOEXPERIMENT=none GOWASM= \
		GOFIPS140=off CGO_ENABLED=0 go env GOROOT
)"
go_binary="${go_root}/bin/go"
if [[ ! -x "${go_binary}" ]]; then
	printf 'selected Go toolchain is missing its executable: %s\n' "${go_binary}" >&2
	exit 1
fi
go_command=(
	env -u GOROOT -u GOOS -u GOARCH
	GO111MODULE=on GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local
	GOEXPERIMENT=none GOWASM= GOFIPS140=off CGO_ENABLED=0
	"${go_binary}"
)
wasm_go_command=(
	env -u GOROOT
	GOOS=js GOARCH=wasm GO111MODULE=on
	GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local
	GOEXPERIMENT=none GOWASM= GOFIPS140=off CGO_ENABLED=0
	"${go_binary}"
)
go_version="$(
	cd "${build_source}"
	"${go_command[@]}" env GOVERSION
)"
go_toolchain="$(
	cd "${build_source}"
	"${go_command[@]}" version
)"
ipa_parameters_json="$(
	cd "${build_source}"
	"${go_command[@]}" run -mod=readonly ./cmd/malt-ipa-parameters
)"

(
	cd "${build_source}"
	"${go_command[@]}" mod verify
	"${wasm_go_command[@]}" build -mod=readonly -buildvcs=false -trimpath \
		-o "${verifier_staging}/malt-verifier.wasm" ./cmd/malt-verifier-wasm
	"${wasm_go_command[@]}" build -mod=readonly -buildvcs=false -trimpath \
		-tags=writer_kzg \
		-o "${writer_staging}/malt-writer-kzg.wasm" ./cmd/malt-writer-wasm
	for profile in direct compact fast; do
		"${wasm_go_command[@]}" build -mod=readonly -buildvcs=false -trimpath \
			-tags=writer_ipa,malt_no_default_kzg \
			-ldflags="-X=main.ipaCommitterProfile=${profile}" \
			-o "${writer_staging}/malt-writer-ipa-${profile}.wasm" ./cmd/malt-writer-wasm
	done
)

cp "${go_root}/lib/wasm/wasm_exec.js" "${verifier_staging}/wasm_exec.js"
cp "${go_root}/lib/wasm/wasm_exec.js" "${writer_staging}/wasm_exec.js"
cp "${build_source}/cmd/malt-writer-wasm/browser/malt-writer-worker.mjs" "${writer_staging}/malt-writer-worker.mjs"
cp "${build_source}/cmd/malt-writer-wasm/browser/malt-writer-workers.mjs" "${writer_staging}/malt-writer-workers.mjs"

MALT_VERSION="${release_version}" MALT_COMMIT="${source_commit}" \
GO_VERSION="${go_version}" GO_TOOLCHAIN="${go_toolchain}" \
PROVENANCE_PATH="${verifier_staging}/PROVENANCE.json" node -e '
	const fs = require("node:fs")
	const provenance = {
		schema: "malt.web-verifier.provenance/v1",
		source_repository: "https://github.com/DeWebProtocol/malt.git",
		source_version: process.env.MALT_VERSION,
		source_commit: process.env.MALT_COMMIT,
		go_version: process.env.GO_VERSION,
		go_toolchain: process.env.GO_TOOLCHAIN,
		target: "js/wasm",
		build_flags: ["-mod=readonly", "-buildvcs=false", "-trimpath"],
		build_environment: {GO111MODULE: "on", GOENV: "off", GOWORK: "off", GOFLAGS: "", GOTOOLCHAIN: "local"},
		codegen_environment: {CGO_ENABLED: "0", GOEXPERIMENT: "none", GOWASM: "", GOFIPS140: "off"}
	}
	fs.writeFileSync(process.env.PROVENANCE_PATH, `${JSON.stringify(provenance, null, 2)}\n`)
'

MALT_VERSION="${release_version}" MALT_COMMIT="${source_commit}" \
GO_VERSION="${go_version}" GO_TOOLCHAIN="${go_toolchain}" \
IPA_PARAMETERS_JSON="${ipa_parameters_json}" \
PROVENANCE_PATH="${writer_staging}/PROVENANCE.json" node -e '
	const fs = require("node:fs")
	const parameters = JSON.parse(process.env.IPA_PARAMETERS_JSON)
	const provenance = {
		schema: "malt.web-writer.provenance/v2",
		source_repository: "https://github.com/DeWebProtocol/malt.git",
		source_version: process.env.MALT_VERSION,
		source_commit: process.env.MALT_COMMIT,
		go_version: process.env.GO_VERSION,
		go_toolchain: process.env.GO_TOOLCHAIN,
		target: "js/wasm",
		parameters,
		build_flags: ["-mod=readonly", "-buildvcs=false", "-trimpath"],
		artifacts: {
			kzg: {file: "malt-writer-kzg.wasm", build_tags: ["writer_kzg"]},
			ipa: {
				direct: {file: "malt-writer-ipa-direct.wasm", build_tags: ["writer_ipa", "malt_no_default_kzg"], linker_profile: "direct", retained_fixed_base_table_bytes: 0},
				compact: {file: "malt-writer-ipa-compact.wasm", build_tags: ["writer_ipa", "malt_no_default_kzg"], linker_profile: "compact", retained_fixed_base_table_bytes: 12582912},
				fast: {file: "malt-writer-ipa-fast.wasm", build_tags: ["writer_ipa", "malt_no_default_kzg"], linker_profile: "fast", retained_fixed_base_table_bytes: 350355456}
			}
		},
		worker_policy: {maximum_active_committers: 1, ipa_fallback: ["fast", "compact", "direct"], cross_backend_fallback: false},
		build_environment: {GO111MODULE: "on", GOENV: "off", GOWORK: "off", GOFLAGS: "", GOTOOLCHAIN: "local"},
		codegen_environment: {CGO_ENABLED: "0", GOEXPERIMENT: "none", GOWASM: "", GOFIPS140: "off"}
	}
	fs.writeFileSync(process.env.PROVENANCE_PATH, `${JSON.stringify(provenance, null, 2)}\n`)
'

chmod 0644 "${verifier_staging}/"* "${writer_staging}/"*
(
	cd "${verifier_staging}"
	sha256sum malt-verifier.wasm wasm_exec.js PROVENANCE.json >SHA256SUMS
)
(
	cd "${writer_staging}"
	sha256sum \
		malt-writer-kzg.wasm \
		malt-writer-ipa-direct.wasm \
		malt-writer-ipa-compact.wasm \
		malt-writer-ipa-fast.wasm \
		malt-writer-worker.mjs \
		malt-writer-workers.mjs \
		wasm_exec.js \
		PROVENANCE.json >SHA256SUMS
)
chmod 0644 "${verifier_staging}/SHA256SUMS" "${writer_staging}/SHA256SUMS"

verifier_digest="$(sha256sum "${verifier_staging}/SHA256SUMS" | awk '{print $1}')"
writer_digest="$(sha256sum "${writer_staging}/SHA256SUMS" | awk '{print $1}')"
verifier_path="verifier/${verifier_digest}"
writer_path="writer/${writer_digest}"
mkdir -p "${release_root}/verifier" "${release_root}/writer"
mv "${verifier_staging}" "${release_root}/${verifier_path}"
mv "${writer_staging}" "${release_root}/${writer_path}"
find "${release_root}" -type d -exec chmod 0755 {} +

tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${source_epoch}" \
	-C "${release_root}" -cf - "${verifier_path}" | gzip -n >"${temporary}/verifier.tar.gz"
tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${source_epoch}" \
	-C "${release_root}" -cf - "${writer_path}" | gzip -n >"${temporary}/writer.tar.gz"
verifier_archive_sha256="$(sha256sum "${temporary}/verifier.tar.gz" | awk '{print $1}')"
writer_archive_sha256="$(sha256sum "${temporary}/writer.tar.gz" | awk '{print $1}')"
verifier_archive="malt-verifier-${release_version}-${verifier_digest}-${verifier_archive_sha256}.tar.gz"
writer_archive="malt-writer-${release_version}-${writer_digest}-${writer_archive_sha256}.tar.gz"
mv "${temporary}/verifier.tar.gz" "${temporary}/${verifier_archive}"
mv "${temporary}/writer.tar.gz" "${temporary}/${writer_archive}"

MALT_VERSION="${release_version}" MALT_COMMIT="${source_commit}" SOURCE_EPOCH="${source_epoch}" \
GO_VERSION="${go_version}" GO_TOOLCHAIN="${go_toolchain}" \
VERIFIER_DIGEST="${verifier_digest}" VERIFIER_ARCHIVE="${verifier_archive}" \
VERIFIER_ARCHIVE_SHA256="${verifier_archive_sha256}" \
WRITER_DIGEST="${writer_digest}" WRITER_ARCHIVE="${writer_archive}" \
WRITER_ARCHIVE_SHA256="${writer_archive_sha256}" \
MANIFEST_PATH="${temporary}/WASM-RELEASE.json" node -e '
	const fs = require("node:fs")
	const component = (kind) => ({
		asset_set_sha256: process.env[`${kind}_DIGEST`],
		path: `${kind.toLowerCase()}/${process.env[`${kind}_DIGEST`]}`,
		archive: process.env[`${kind}_ARCHIVE`],
		archive_sha256: process.env[`${kind}_ARCHIVE_SHA256`]
	})
	const manifest = {
		schema: "malt.wasm-release/v1",
		source_repository: "https://github.com/DeWebProtocol/malt.git",
		source_version: process.env.MALT_VERSION,
		source_commit: process.env.MALT_COMMIT,
		source_epoch: Number(process.env.SOURCE_EPOCH),
		go_version: process.env.GO_VERSION,
		go_toolchain: process.env.GO_TOOLCHAIN,
		target: "js/wasm",
		archive_format: "ustar+gzip",
		codegen_environment: {CGO_ENABLED: "0", GOEXPERIMENT: "none", GOWASM: "", GOFIPS140: "off"},
		components: {verifier: component("VERIFIER"), writer: component("WRITER")}
	}
	fs.writeFileSync(process.env.MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`)
'
manifest_digest="$(sha256sum "${temporary}/WASM-RELEASE.json" | awk '{print $1}')"
manifest_name="malt-wasm-release-${release_version}-${manifest_digest}.json"
mv "${temporary}/WASM-RELEASE.json" "${temporary}/${manifest_name}"
(
	cd "${temporary}"
	sha256sum "${verifier_archive}" "${writer_archive}" "${manifest_name}" >SHA256SUMS
)

for artifact in "${verifier_archive}" "${writer_archive}" "${manifest_name}" SHA256SUMS; do
	install -m 0644 "${temporary}/${artifact}" "${output_dir}/${artifact}"
done
"${repo_root}/scripts/check-wasm-release.sh" "${output_dir}"
printf 'built MALT WASM release assets in %s\n' "${output_dir}"
