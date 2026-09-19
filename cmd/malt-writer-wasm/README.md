# Browser Client-Root Writer

Build the coordinated browser writer artifact set from the repository root:

```bash
scripts/build-writer-wasm.sh dist/writer
```

The build emits four immutable backend/profile WASM modules plus one Worker and
one single-instance controller:

```text
malt-writer-kzg.wasm
malt-writer-ipa-direct.wasm
malt-writer-ipa-compact.wasm
malt-writer-ipa-fast.wasm
malt-writer-worker.mjs
malt-writer-workers.mjs
wasm_exec.js
```

The three IPA modules use the same SRS, transcripts, proof encoding, typed CID,
and writer wire profiles. They differ only in their fixed-base MSM strategy:

| profile | retained fixed-base table | intended use |
|---|---:|---|
| `direct` | 0 bytes | low-memory fallback; generic MSM per commitment |
| `compact` | 12,582,912 bytes plus table metadata | browser default |
| `fast` | 350,355,456 bytes plus table metadata | explicit high-memory performance opt-in |

The verifier uses `ipa.NewVerifierScheme()` and does not retain any of these
tables. The figures above cover the curve-point table only, not the Go/WASM
runtime, session views, prepared candidates, or transient allocations.

## Single Worker controller

```js
import { createMaltWriterWorker } from "./malt-writer-workers.mjs";

const writer = await createMaltWriterWorker({
  backend: "ipa",
  profile: "compact",
  wasmURL: new URL("./malt-writer-ipa-compact.wasm", import.meta.url),
});
await writer.ready;
```

One controller owns exactly one immutable backend/profile Worker. It never
starts a peer backend or switches the loaded implementation. Applications may
terminate it and construct another controller only when no writer session or
prepared candidate is active. An IPA loader may fall back
`fast -> compact -> direct`, but must never reinterpret an IPA root as KZG.

`writer.fatal` is a once-settling Promise for lifecycle observation. It resolves
with the fatal `Error` if initialization or the running Worker fails, including
while no RPC is active, and never rejects. Explicit `terminate()` is a normal
lifecycle transition and does not resolve `fatal`. Subscribers attached after
a failure observe the same already-resolved Promise.

An `AbortSignal` releases initialization callers immediately during fetch,
response decoding, or WebAssembly compilation and prevents a late Worker from
starting. Browser WebAssembly compilation promises are not themselves
cancellable, however, so the engine may finish an already-started compilation
in the background; its late resolution or rejection is observed and discarded.

The controller retains the backend argument in every method so typed-root
routing remains explicit:

```text
compute(backend, transactionIDUTF8, updateViewJSONUTF8, semanticIntentJSONUTF8)
bootstrap(backend)
load(backend, updateViewJSONUTF8)
prepare(backend, transactionIDUTF8, semanticIntentJSONUTF8)
getPreparedResult(backend, transactionIDUTF8)
validateReceipt(backend, writerResultJSONUTF8, materializationReceiptJSONUTF8)
acceptReceipt(backend, transactionIDUTF8, materializationReceiptJSONUTF8)
discard(backend, transactionIDUTF8)
closeSession(backend)
terminate()
```

All byte arguments are strict `Uint8Array` values. Operation IDs contain at
most 128 ASCII bytes; JSON inputs use the checked-in client-root wire profiles
and the protocol 64 MiB document limit.

## Session and trust behavior

`bootstrap` creates and retains the canonical empty-map base. `load` verifies a
complete update view once. `prepare` retains an exact candidate while
`getPreparedResult` returns `malt.writer-compute-result/v3`. Only an exact
`malt.materialization-receipt/v2` advances the session through `acceptReceipt`.

At most 64 candidates and 64 MiB of encoded prepared responses are retained.
Accepting one candidate invalidates its speculative peers. `discard` and
`closeSession` release unreachable materialized snapshots. The writer computes
locally; it does not contact a Gateway, publish a root, or promote a candidate
to trusted state.

The implementation profile is exposed only by the Worker ready/status
handshake. It is not serialized into a CID, ProofList, client-root bundle,
UpdateView, receipt digest, or Gateway acceptance input.

## Direct runtime API

Each backend-specific artifact registers:

```text
globalThis.maltComputeClientRootV1(...)
globalThis.maltWriterBootstrapSessionV1()
globalThis.maltWriterLoadSessionV1(...)
globalThis.maltWriterPrepareSessionV1(...)
globalThis.maltWriterGetPreparedResultV1(...)
globalThis.maltWriterValidateReceiptV1(...)
globalThis.maltWriterAcceptSessionReceiptV1(...)
globalThis.maltWriterDiscardSessionCandidateV1(...)
globalThis.maltWriterCloseSessionV1()
```

`maltWriterLoadedBackend` and `maltWriterLoadedProfile` let the Worker reject an
artifact/selection mismatch before it becomes ready. IPA profiles are fixed at
link time; JavaScript cannot mutate them.

Run dependency-isolation checks, controller tests, native fixtures, all four
real-WASM stateless/session smokes, and the single-Worker smoke with:

```bash
scripts/test-writer-wasm.sh
```
