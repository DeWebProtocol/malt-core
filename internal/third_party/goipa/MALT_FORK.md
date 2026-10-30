# MALT go-ipa fork

This directory is a source copy of
`github.com/crate-crypto/go-ipa@53bbb0ceb27adb011950fd0fce885ad6d4516f84`.
The upstream project is licensed under the included Apache-2.0 and MIT
licenses.

The source is compiled as packages inside the MALT module (rather than as a
nested module or a relative `replace`) so tagged and pseudo-version consumers
receive the exact pinned source snapshot.

MALT carries the copy because upstream exposes only one fixed-base MSM setup:
a roughly 334 MiB Verkle-optimized table. The local patch adds verifier-only,
direct, compact 4-bit, and original fast settings while preserving the SRS,
transcripts, commitment bytes, and proof encoding. Keep changes narrow and
validate all profiles against the upstream fast output before updating the
source snapshot.

The behavioral patch covers `ipa/config.go`, `banderwagon/precomp.go`,
`multiproof.go`, `bandersnatch/multiexp.go`, and `common/parallel/execute.go`.
Import paths are mechanically rewritten to the internal MALT location.
Upstream test files are not copied; MALT owns profile equivalence, parallel
execution tests, 32-bit, and real-WASM conformance coverage at the integration
boundary.

Execution budgets follow the current `runtime.GOMAXPROCS(0)` rather than the
host's logical CPU count, including generic MSM, precomputation, and multiproof
aggregation. Fast and compact fixed-base commitments partition nonzero terms
into private accumulators and reduce them in a fixed order. Each task receives
at least eight terms; smaller commitments stay serial. IPA point folding runs
independent scalar multiplications in parallel, with at least four points per
task and serial final rounds. The generic MSM still schedules its internal
radix chunks; its task setting is not a global goroutine limit. All profiles,
CPU budgets, and concurrent callers must produce identical canonical commitment
and proof bytes. SRS generation, transcript order, and wire formats are unchanged.
