import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync, gunzipSync } from 'node:zlib'

const [releaseDirectory] = process.argv.slice(2)
if (!releaseDirectory) {
  throw new Error('usage: test-wasm-release-adversarial.mjs release-directory')
}

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const checker = join(repoRoot, 'scripts', 'check-wasm-release.sh')
const temporary = mkdtempSync(join(tmpdir(), 'malt-wasm-release-adversarial.'))

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function onlyEntry(directory, pattern, label) {
  const entries = readdirSync(directory).filter((entry) => pattern.test(entry))
  if (entries.length !== 1) {
    throw new Error(`${directory} must contain exactly one ${label}`)
  }
  return entries[0]
}

function tarHeaderOffsets(tarBytes) {
  const offsets = []
  for (let offset = 0; offset + 512 <= tarBytes.length;) {
    const block = tarBytes.subarray(offset, offset + 512)
    if (block.every((byte) => byte === 0)) break
    const sizeText = block
      .subarray(124, 136)
      .toString('ascii')
      .replace(/\0.*$/s, '')
      .trim()
    if (!/^[0-7]+$/.test(sizeText)) throw new Error('invalid fixture tar size')
    const size = Number.parseInt(sizeText, 8)
    offsets.push(offset)
    offset += 512 + Math.ceil(size / 512) * 512
  }
  return offsets
}

function updateHeaderChecksum(tarBytes, offset) {
  const block = tarBytes.subarray(offset, offset + 512)
  block.fill(0x20, 148, 156)
  let checksum = 0
  for (const byte of block) checksum += byte
  const digits = checksum.toString(8)
  if (digits.length > 6) throw new Error('fixture checksum overflow')
  block.write(`${digits.padStart(6, '0')}\0 `, 148, 8, 'binary')
}

function retargetRelease(directory, mutate) {
  const manifestName = onlyEntry(
    directory,
    /^malt-wasm-release-.+\.json$/,
    'release manifest'
  )
  const manifestPath = join(directory, manifestName)
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const oldArchive = manifest.components.verifier.archive
  const oldArchivePath = join(directory, oldArchive)
  const tarBytes = gunzipSync(readFileSync(oldArchivePath))
  const offsets = tarHeaderOffsets(tarBytes)
  if (offsets.length < 2) throw new Error('verifier fixture has no regular file header')

  mutate(tarBytes, offsets)
  const mutatedArchive = gzipSync(tarBytes, { mtime: 0 })
  const canonicalGzipHeader = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03])
  if (!mutatedArchive.subarray(0, 10).equals(canonicalGzipHeader)) {
    throw new Error('fixture compressor did not emit the canonical gzip header')
  }

  const archiveSHA = sha256(mutatedArchive)
  const newArchive = [
    'malt-verifier',
    manifest.source_version,
    manifest.components.verifier.asset_set_sha256,
    `${archiveSHA}.tar.gz`
  ].join('-')
  writeFileSync(join(directory, newArchive), mutatedArchive)
  unlinkSync(oldArchivePath)
  manifest.components.verifier.archive = newArchive
  manifest.components.verifier.archive_sha256 = archiveSHA

  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)
  const newManifest = `malt-wasm-release-${manifest.source_version}-${sha256(manifestBytes)}.json`
  writeFileSync(join(directory, newManifest), manifestBytes)
  unlinkSync(manifestPath)

  const covered = [newArchive, manifest.components.writer.archive, newManifest]
  const checksumBytes = Buffer.from(
    `${covered.map((name) => `${sha256(readFileSync(join(directory, name)))}  ${name}`).join('\n')}\n`
  )
  writeFileSync(join(directory, 'SHA256SUMS'), checksumBytes)
}

function mutateField(tarBytes, offset, length, value) {
  const block = tarBytes.subarray(0, 512)
  block.fill(0, offset, offset + length)
  Buffer.from(value, 'binary').copy(block, offset)
  updateHeaderChecksum(tarBytes, 0)
}

const cases = [
  {
    name: 'uname',
    mutate: (tarBytes) => mutateField(tarBytes, 265, 32, 'root')
  },
  {
    name: 'gname',
    mutate: (tarBytes) => mutateField(tarBytes, 297, 32, 'root')
  },
  {
    name: 'linkname',
    mutate(tarBytes, offsets) {
      const offset = offsets[1]
      const block = tarBytes.subarray(offset, offset + 512)
      block.write('ignored', 157, 'ascii')
      updateHeaderChecksum(tarBytes, offset)
    }
  },
  {
    name: 'device-fields',
    mutate(tarBytes, offsets) {
      const offset = offsets[1]
      const block = tarBytes.subarray(offset, offset + 512)
      block.write('0000000\0', 329, 8, 'binary')
      updateHeaderChecksum(tarBytes, offset)
    }
  },
  {
    name: 'null-file-typeflag',
    mutate(tarBytes, offsets) {
      const offset = offsets[1]
      tarBytes[offset + 156] = 0
      updateHeaderChecksum(tarBytes, offset)
    }
  },
  {
    name: 'alternate-mode-encoding',
    mutate(tarBytes) {
      tarBytes.write(' 000755\0', 100, 8, 'binary')
      updateHeaderChecksum(tarBytes, 0)
    }
  },
  {
    name: 'nonzero-name-padding',
    mutate(tarBytes) {
      const zero = tarBytes.subarray(0, 100).indexOf(0)
      if (zero < 0 || zero + 1 >= 100) throw new Error('fixture name has no spare padding')
      tarBytes[zero + 1] = 0x58
      updateHeaderChecksum(tarBytes, 0)
    }
  }
]

try {
  const valid = spawnSync(checker, [releaseDirectory], { encoding: 'utf8' })
  if (valid.status !== 0) {
    throw new Error(`valid release failed verification:\n${valid.stdout}${valid.stderr}`)
  }

  for (const testCase of cases) {
    const caseDirectory = join(temporary, testCase.name)
    cpSync(releaseDirectory, caseDirectory, { recursive: true })
    retargetRelease(caseDirectory, testCase.mutate)
    const checked = spawnSync(checker, [caseDirectory], { encoding: 'utf8' })
    if (checked.status === 0) {
      throw new Error(`release checker accepted non-canonical ${testCase.name} metadata`)
    }
    const output = `${checked.stdout}${checked.stderr}`
    if (!output.includes('does not use canonical ustar+gzip encoding')) {
      throw new Error(`non-canonical ${testCase.name} failed outside raw archive validation:\n${output}`)
    }
  }
} finally {
  rmSync(temporary, { recursive: true, force: true })
}

console.log(`Rejected ${cases.length} self-consistent releases with non-canonical ustar headers.`)
