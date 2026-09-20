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
for (const name of ['Create', 'Import', 'Apply', 'Export', 'Discard', 'Close']) {
  assert.equal(typeof globalThis[`malt${name}Authentication`], 'function', name)
}
const text = value => new TextEncoder().encode(value)
const json = value => text(JSON.stringify(value))
const first = 'bafkqaaa'
const second = 'bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta'
const state = {
  descriptor: { layout: 2, input_rule: 0, vc_profile: backend === 'ipa' ? 2 : 1 },
  entries: Array.from({ length: 256 }, (_, i) => ({
    input: { kind: 'index', number: String(i) }, target: { '/': first }
  }))
}
const base = JSON.parse(await globalThis.maltCreateAuthentication(json(state)))
assert.equal(typeof base.handle, 'string')
assert.equal(base.nodes, undefined)
const delta = {
  profile: 'malt.authentication-delta/0',
  changes: [{ input: { kind: 'index', number: '255' }, before: first, after: second }]
}
const next = JSON.parse(await globalThis.maltApplyAuthentication(text(base.handle), json(delta)))
assert.notEqual(next.root, base.root)
assert.equal(next.nodes, undefined)
state.entries[255].target['/'] = second
const fresh = JSON.parse(await globalThis.maltPrepareAuthentication(json(state)))
assert.equal(next.root, fresh.root)
const exported = JSON.parse(await globalThis.maltExportAuthentication(text(next.handle)))
assert.equal(exported.root, next.root)
assert.equal(exported.previous, base.root)
assert(exported.nodes.length > 0)
const imported = JSON.parse(await globalThis.maltImportAuthentication(json(exported)))
assert.equal(imported.root, next.root)
await assert.rejects(() => globalThis.maltApplyAuthentication(text(next.handle), json(delta)))
const original = JSON.parse(await globalThis.maltExportAuthentication(text(base.handle)))
assert.equal(original.root, base.root)
await globalThis.maltDiscardAuthentication(text(base.handle))
await assert.rejects(() => globalThis.maltExportAuthentication(text(base.handle)))
await globalThis.maltCloseAuthentication()
await assert.rejects(() => globalThis.maltExportAuthentication(text(next.handle)))
const restarted = JSON.parse(await globalThis.maltCreateAuthentication(json(state)))
assert.notEqual(restarted.handle, base.handle)
assert.notEqual(restarted.handle, next.handle)
await assert.rejects(() => globalThis.maltApplyAuthentication(text(restarted.handle), json({ ...delta, count: null })))
console.log(`Retained authentication ${backend}/${profile || 'default'}: branch, export, import, rejection and release checks passed`)
process.exit(0)
