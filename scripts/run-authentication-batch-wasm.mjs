import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

const [wasm, runtime, backend, profile = ''] = process.argv.slice(2)
assert(['kzg', 'ipa'].includes(backend))
globalThis.crypto ??= webcrypto
await import(pathToFileURL(runtime).href)
const go = new globalThis.Go()
go.argv = ['malt-writer.wasm', `--backend=${backend}`]
const { instance } = await WebAssembly.instantiate(await readFile(wasm), go.importObject)
let failure
void go.run(instance).catch(error => { failure = error })
const deadline = Date.now() + 120000
while (!globalThis.maltWriterReady) {
  if (failure) throw failure
  assert(Date.now() < deadline, 'writer startup timed out')
  await new Promise(resolve => setTimeout(resolve, 10))
}
assert.equal(globalThis.maltWriterInitError, undefined)
assert.equal(globalThis.maltWriterLoadedBackend, backend)
assert.equal(globalThis.maltWriterLoadedProfile, profile)
for (const name of ['maltComputeClientRootV1', 'maltWriterBootstrapSessionV1', 'maltWriterLoadSessionV1', 'maltWriterPrepareSessionV1', 'maltWriterValidateReceiptV1']) assert.equal(globalThis[name], undefined)
const json = value => new TextEncoder().encode(JSON.stringify(value))
const state = { descriptor: { layout: 1, input_rule: 1, vc_profile: backend === 'ipa' ? 2 : 1 }, entries: [] }
const base = JSON.parse(await globalThis.maltPrepareAuthentication(json(state)))
state.entries.push({ input: { kind: 'label', data: 'ZmlsZQ==' }, target: { '/': 'bafkqaaa' } })
const next = JSON.parse(await globalThis.maltUpdateAuthentication(json(base), json(state)))
// Both complete and retained no-op updates must stay materializable.
const unchanged = JSON.parse(await globalThis.maltUpdateAuthentication(json(next), json(state)))
const retained = JSON.parse(await globalThis.maltImportAuthentication(json(next)))
const noOpHandle = JSON.parse(await globalThis.maltApplyAuthentication(new TextEncoder().encode(retained.handle), json({ profile: 'malt.authentication-delta/0', changes: [] })))
const noOp = JSON.parse(await globalThis.maltExportAuthentication(new TextEncoder().encode(noOpHandle.handle)))
for (const candidate of [unchanged, noOp]) {
  assert.equal(candidate.root, next.root)
  assert.equal(candidate.previous, next.previous)
  const noOpBatch = { profile: 'malt.authentication-batch/0', transaction_id: 'no-op', base: next.root, root: next.root, candidates: [candidate] }
  const noOpDigest = await globalThis.maltValidateAuthenticationBatch(json(noOpBatch))
  assert.equal(await globalThis.maltValidateAuthenticationReceipt(json(noOpBatch), json({ profile: 'malt.authentication-receipt/0', transaction_id: noOpBatch.transaction_id, base: next.root, root: next.root, digest: noOpDigest, durable_boundary: 'wasm-test/no-op' })), next.root)
}
await globalThis.maltCloseAuthentication()
const batch = { profile: 'malt.authentication-batch/0', transaction_id: 'wasm-batch', base: base.root, root: next.root, candidates: [base, next] }
const digest = await globalThis.maltValidateAuthenticationBatch(json(batch))
assert.match(digest, /^[a-f0-9]{64}$/)
const receipt = { profile: 'malt.authentication-receipt/0', transaction_id: batch.transaction_id, base: batch.base, root: batch.root, digest, durable_boundary: 'wasm-test/0' }
assert.equal(await globalThis.maltValidateAuthenticationReceipt(json(batch), json(receipt)), next.root)
for (const field of ['transaction_id', 'base', 'root', 'digest', 'durable_boundary']) {
  await assert.rejects(() => globalThis.maltValidateAuthenticationReceipt(json(batch), json({ ...receipt, [field]: '' })))
}
const changed = structuredClone(batch)
changed.candidates[1].state.entries[0].target = { '/': 'bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta' }
await assert.rejects(() => globalThis.maltValidateAuthenticationBatch(json(changed)))
await assert.rejects(() => globalThis.maltValidateAuthenticationReceipt(json(changed), json(receipt)))
await assert.rejects(() => globalThis.maltValidateAuthenticationBatch(json({ ...batch, candidates: [...batch.candidates].reverse() })))
await assert.rejects(() => globalThis.maltValidateAuthenticationBatch('{}'))
console.log(`Typed WASM batch ${backend}/${profile}: candidate verification, order and exact receipt checks passed`)
process.exit(0)
