# Browser authentication writer

`scripts/build-writer-wasm.sh dist/writer` emits coordinated KZG, IPA direct,
compact, and fast modules, matching `wasm_exec.js`, and the Worker/controller
modules. One controller owns exactly one backend/profile runtime. The
supported TypeScript package and distributed release lock belong to malt-ts.

| IPA execution profile | Retained fixed-base point table |
| --- | ---: |
| `direct` | 0 bytes |
| `compact` | 12,582,912 bytes |
| `fast` | 350,355,456 bytes |

These profiles produce identical Roots/proofs. Table sizes exclude runtime,
metadata, retained candidates, and transient allocations. KZG has no IPA
profile. Runtime selection must match the artifact exactly before ready.

```js
import { createMaltWriterWorker } from './malt-writer-workers.mjs'
const writer = await createMaltWriterWorker({
  backend: 'ipa', profile: 'compact',
  wasmURL: new URL('./malt-writer-ipa-compact.wasm', import.meta.url),
})
await writer.ready
```

## Current controller API

All methods receive the selected backend as their first argument. JSON and
handle arguments below are UTF-8 `Uint8Array` values. Returned host results are
JSON strings; discard and close return the host completion string.

```text
prepareAuthentication(backend, stateJSON) -> complete candidate
updateAuthentication(backend, candidateJSON, stateJSON) -> complete candidate
createAuthentication(backend, stateJSON) -> {handle, root}
importAuthentication(backend, candidateJSON) -> {handle, root}
applyAuthentication(backend, handle, deltaJSON) -> {handle, root}
exportAuthentication(backend, handle) -> complete candidate
discardAuthentication(backend, handle)
closeAuthentication(backend)
validateAuthenticationBatch(backend, batchJSON) -> validation result/digest
validateAuthenticationReceipt(backend, batchJSON, receiptJSON) -> validation result
terminate()
```

Create/import/apply/export/discard/close are serialized in Worker order.
Import verifies complete external state once; apply retains an independent
branch and export is explicit. By default at most 64 handles and 64 MiB of
conservative state charge are retained. Closing clears handles without reusing
old identifiers. A full-buffer candidate import may transfer its buffer to the
Worker; callers must not reuse a detached buffer.

Batch verification and exact receipt checks use Core's current contracts.
Applications own receipt-driven graph/session advancement, retries, persistence,
publication, and accepted-root promotion. Handles and receipts are not portable
state-transition proofs. No old client-root or UpdateView session API remains.

The controller's `fatal` Promise resolves once with fatal runtime failure and
never rejects. Explicit termination is a normal lifecycle action. AbortSignal
cancels pending initialization callers; already started browser compilation may
finish, but late completion cannot start a Worker. Every ready/response/failure
message must name the exact loaded backend/profile.

## Direct runtime ABI

Each module must register all ten exports before the Worker becomes ready:

```text
maltPrepareAuthentication, maltUpdateAuthentication
maltCreateAuthentication, maltImportAuthentication, maltApplyAuthentication
maltExportAuthentication, maltDiscardAuthentication, maltCloseAuthentication
maltValidateAuthenticationBatch, maltValidateAuthenticationReceipt
```

Each export returns a Promise and takes bounded UTF-8 `Uint8Array` arguments.
Current JSON documents have a 96 MiB limit; handles use canonical decimal IDs
with at most 20 bytes. `maltWriterLoadedBackend` and `maltWriterLoadedProfile`
are checked at initialization; profile identity is fixed at link time.

Run `scripts/test-writer-wasm.sh` for backend dependency isolation, controller
lifecycle, all four real WASM candidate/session/batch tests, and a real Worker.
Use the workspace resource scope for build/test commands.
