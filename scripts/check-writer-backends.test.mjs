import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const scripts = dirname(fileURLToPath(import.meta.url))
const commands = Object.fromEntries(['sh', 'dirname', 'mktemp', 'rm', 'grep'].map(name => [
  name, execFileSync('/bin/sh', ['-c', `command -v ${name}`], { encoding: 'utf8' }).trim()
]))

// A deliberately small PATH has no rg, even when the developer machine does.
// Test the real gate as a process, with controlled dependency-query output.
function runGate(t, { entry = 'check-writer-backends.sh', missing, grepStatus, leak, queryFailure } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'malt-writer-gate-test.'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const bin = join(root, 'bin')
  const callLog = join(root, 'queries')
  const reachedTests = join(root, 'reached-tests')
  mkdirSync(bin)
  for (const [name, executable] of Object.entries(commands)) {
    if (name !== missing && !(name === 'grep' && grepStatus !== undefined)) {
      symlinkSync(executable, join(bin, name))
    }
  }
  const executable = (name, contents) => writeFileSync(join(bin, name), `#!/bin/sh\n${contents}\n`, { mode: 0o755 })
  if (missing !== 'go') {
    executable('go', `set -eu
case "$*" in
  *-tags=writer_kzg*) backend=kzg; excluded=ipa ;;
  *-tags=writer_ipa,malt_no_default_kzg*) backend=ipa; excluded=kzg ;;
  *) exit 96 ;;
esac
if [ "\${GOOS:-}" = js ] && [ "\${GOARCH:-}" = wasm ]; then target=wasm; else target=native; fi
printf '%s\\n' "$backend-$target" >> "$CALL_LOG"
printf '%s\\n' "github.com/dewebprotocol/malt-core/auth/commitment/$backend"
if [ "$QUERY_FAILURE" = "$backend-$target" ]; then exit 17; fi
if [ "$LEAK" = "$backend-$target" ]; then
  printf '%s\\n' "github.com/dewebprotocol/malt-core/auth/commitment/$excluded"
fi`)
  }
  if (grepStatus !== undefined) executable('grep', `exit ${grepStatus}`)
  // If the full writer gate fails to propagate an isolation error, this marks
  // that it reached the unrelated Node/WASM work before deliberately failing.
  executable('node', 'printf reached > "$REACHED_TESTS"\nexit 93')
  const result = spawnSync(commands.sh, [join(scripts, entry)], {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env, PATH: bin, TMPDIR: root, GOOS: '', GOARCH: '',
      CALL_LOG: callLog, REACHED_TESTS: reachedTests,
      LEAK: leak ?? '', QUERY_FAILURE: queryFailure ?? ''
    }
  })
  assert.ifError(result.error)
  assert.equal(result.signal, null)
  return {
    ...result,
    queries: existsSync(callLog) ? readFileSync(callLog, 'utf8').trim().split('\n') : [],
    reachedTests: existsSync(reachedTests)
  }
}

test('valid dependencies pass without rg and query all four builds', t => {
  const result = runGate(t)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.queries, ['kzg-native', 'kzg-wasm', 'ipa-native', 'ipa-wasm'])
  assert.match(result.stdout, /kzg writer: native and js\/wasm dependencies exclude ipa/)
  assert.match(result.stdout, /ipa writer: native and js\/wasm dependencies exclude kzg/)
})

for (const backend of ['kzg', 'ipa']) {
  for (const target of ['native', 'wasm']) {
    const key = `${backend}-${target}`
    test(`${key} rejects an extra backend when rg is absent`, t => {
      const result = runGate(t, { leak: key })
      assert.equal(result.status, 1, result.stderr)
      assert.match(result.stderr, new RegExp(`${backend} writer unexpectedly links`))
    })
    test(`${key} rejects failed go list even after partial output`, t => {
      const result = runGate(t, { queryFailure: key })
      assert.equal(result.status, 17, result.stderr)
      assert.equal(result.queries.at(-1), key)
    })
  }
}

for (const missing of ['go', 'grep']) {
  test(`missing ${missing} fails preflight`, t => {
    const result = runGate(t, { missing })
    assert.equal(result.status, 127, result.stderr)
    assert.match(result.stderr, new RegExp(`required command not found: ${missing}`))
    assert.deepEqual(result.queries, [])
  })
}

for (const grepStatus of [2, 126, 127]) {
  test(`grep exit ${grepStatus} is an execution failure, not absence`, t => {
    const result = runGate(t, { grepStatus })
    assert.equal(result.status, grepStatus, result.stderr)
    assert.match(result.stderr, new RegExp(`dependency matching failed \\(grep exit ${grepStatus}\\)`))
  })
}

for (const options of [{ missing: 'grep' }, { grepStatus: 2 }, { leak: 'ipa-wasm' }, { queryFailure: 'kzg-native' }]) {
  test(`writer smoke stops before Node/WASM on ${JSON.stringify(options)}`, t => {
    const result = runGate(t, { entry: 'test-writer-wasm.sh', ...options })
    assert.notEqual(result.status, 0)
    assert.equal(result.reachedTests, false, result.stderr)
  })
}
