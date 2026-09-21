import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

const [kind, wasm, runtime, corpusPath, backend = 'all'] = process.argv.slice(2)
assert(['verifier', 'writer'].includes(kind), 'select verifier or writer')
assert(['all', 'kzg', 'ipa'].includes(backend), 'select all, kzg, or ipa')
globalThis.crypto ??= webcrypto
await import(pathToFileURL(runtime).href)
const go = new globalThis.Go()
go.argv = ['malt.wasm', `--backend=${backend}`]
globalThis.maltVerifierBackend = backend
const { instance } = await WebAssembly.instantiate(await readFile(wasm), go.importObject)
let failure
void go.run(instance).catch(error => { failure = error })
const name = kind === 'verifier' ? 'maltVerifyAuthentication' : 'maltPrepareAuthentication'
const deadline = Date.now() + 120000
while (typeof globalThis[name] !== 'function') {
  if (failure) throw failure
  assert(Date.now() < deadline, 'WASM initialization timed out')
  await new Promise(resolve => setTimeout(resolve, 10))
}
const corpus = JSON.parse(await readFile(corpusPath, 'utf8'))
assert.equal(corpus.schema, 'malt.conformance.authentication/1')
if (kind === 'verifier') {
  for (const vector of corpus.vectors) {
    const result = JSON.parse(globalThis[name](JSON.stringify(vector.verification)))
    assert.equal(result.profile, vector.verification.request.profile, vector.id)
    const profile = /^profile-([12])\./.exec(vector.id)?.[1]
    assert(profile, `unknown vector profile: ${vector.id}`)
    const installed = backend === 'all' || profile === (backend === 'kzg' ? '1' : '2')
    assert.equal(result.valid, vector.valid && installed, `${vector.id}: ${result.error || ''}`)
    if (vector.valid && !installed) assert.match(result.error, /VC profile [12] is not installed/)
  }
  assert.equal(JSON.parse(globalThis[name]('{}')).valid, false)
  console.log(`V0 WASM verifier ${backend} passed: ${corpus.vectors.length} vectors`)
} else {
  const id = backend === 'ipa' ? 2 : 1
  const state = { descriptor: { layout: 1, input_rule: 1, vc_profile: id }, entries: [
    { input: { kind: 'label', data: 'YS9i' }, target: { '/': 'bafkqaaa' } },
    { input: { kind: 'system', number: '1' }, target: { '/': 'bafkqaaa' } }
  ] }
  const candidate = JSON.parse(await globalThis[name](new TextEncoder().encode(JSON.stringify(state))))
  const expected = corpus.vectors.find(v => v.id === `profile-${id}.opaque-label`)
  assert.equal(candidate.root, expected.verification.request.root)
  assert.equal(candidate.profile, 'malt.authentication/0')
  assert(candidate.nodes.length > 0)
  await assert.rejects(() => globalThis[name]('{}'))
  state.descriptor.input_rule = 255
  await assert.rejects(() => globalThis[name](new TextEncoder().encode(JSON.stringify(state))))
  console.log(`V0 WASM writer ${backend}: exact native Root and rejection checks passed`)
}
process.exit(0)
