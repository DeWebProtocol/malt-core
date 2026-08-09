import { openSync, readSync, closeSync, createReadStream } from 'node:fs'
import { createGunzip } from 'node:zlib'

const [archivePath, expectedRoot, epochText, ...filenames] = process.argv.slice(2)
if (!archivePath || !expectedRoot || !/^[0-9]+$/.test(epochText || '')) {
  throw new Error('usage: check-wasm-archive.mjs archive root source-epoch files...')
}

const sourceEpoch = Number(epochText)
if (!Number.isSafeInteger(sourceEpoch) || sourceEpoch <= 0) {
  throw new Error('source epoch must be a positive safe integer')
}

const gzipHeader = Buffer.alloc(10)
const descriptor = openSync(archivePath, 'r')
try {
  if (readSync(descriptor, gzipHeader, 0, gzipHeader.length, 0) !== gzipHeader.length) {
    throw new Error('gzip archive is shorter than its fixed header')
  }
} finally {
  closeSync(descriptor)
}
const canonicalGzipHeader = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03])
if (!gzipHeader.equals(canonicalGzipHeader)) {
  throw new Error('archive does not use the canonical gzip -n header')
}

const expectedEntries = [
  { path: `${expectedRoot}/`, type: 'directory', mode: 0o755 },
  ...filenames.map((filename) => ({
    path: `${expectedRoot}/${filename}`,
    type: 'file',
    mode: 0o644
  }))
]

function fieldString(block, offset, length) {
  const field = block.subarray(offset, offset + length)
  const zero = field.indexOf(0)
  return field.subarray(0, zero < 0 ? field.length : zero).toString('ascii')
}

function octalField(block, offset, length, label) {
  const value = fieldString(block, offset, length).trim()
  if (!/^[0-7]+$/.test(value)) throw new Error(`invalid ustar ${label}`)
  return Number.parseInt(value, 8)
}

function headerChecksum(block) {
  const copy = Buffer.from(block)
  copy.fill(0x20, 148, 156)
  let sum = 0
  for (const byte of copy) sum += byte
  return sum
}

let buffered = Buffer.alloc(0)
let contentBytes = 0
let paddingBytes = 0
let entryIndex = 0
let zeroBlocks = 0

function consume(chunk) {
  buffered = buffered.length === 0 ? chunk : Buffer.concat([buffered, chunk])
  while (buffered.length > 0) {
    if (contentBytes > 0) {
      const consumed = Math.min(contentBytes, buffered.length)
      buffered = buffered.subarray(consumed)
      contentBytes -= consumed
      continue
    }
    if (paddingBytes > 0) {
      const consumed = Math.min(paddingBytes, buffered.length)
      if (!buffered.subarray(0, consumed).every((byte) => byte === 0)) {
        throw new Error('tar payload padding is not canonical zero padding')
      }
      buffered = buffered.subarray(consumed)
      paddingBytes -= consumed
      continue
    }
    if (buffered.length < 512) return
    const block = buffered.subarray(0, 512)
    buffered = buffered.subarray(512)
    if (block.every((byte) => byte === 0)) {
      zeroBlocks += 1
      continue
    }
    if (zeroBlocks > 0) throw new Error('non-zero tar header follows end marker')
    if (entryIndex >= expectedEntries.length) throw new Error('unexpected raw tar member')
    if (
      block.subarray(257, 263).toString('binary') !== 'ustar\0' ||
      block.subarray(263, 265).toString('ascii') !== '00'
    ) {
      throw new Error('archive member is not encoded as POSIX ustar')
    }

    const name = fieldString(block, 0, 100)
    const prefix = fieldString(block, 345, 155)
    const path = prefix ? `${prefix}/${name}` : name
    const typeFlag = block[156]
    const actualType = typeFlag === 0x35
      ? 'directory'
      : typeFlag === 0 || typeFlag === 0x30
        ? 'file'
        : 'unsupported'
    const expected = expectedEntries[entryIndex]
    if (path !== expected.path || actualType !== expected.type) {
      throw new Error(`unexpected raw tar member ${JSON.stringify(path)}`)
    }

    const mode = octalField(block, 100, 8, 'mode')
    const uid = octalField(block, 108, 8, 'uid')
    const gid = octalField(block, 116, 8, 'gid')
    const size = octalField(block, 124, 12, 'size')
    const mtime = octalField(block, 136, 12, 'mtime')
    const checksum = octalField(block, 148, 8, 'checksum')
    if (
      mode !== expected.mode || uid !== 0 || gid !== 0 ||
      mtime !== sourceEpoch || checksum !== headerChecksum(block) ||
      (expected.type === 'directory' && size !== 0)
    ) {
      throw new Error(`non-canonical raw ustar metadata for ${path}`)
    }

    contentBytes = size
    paddingBytes = (512 - (size % 512)) % 512
    entryIndex += 1
  }
}

for await (const chunk of createReadStream(archivePath).pipe(createGunzip())) {
  consume(chunk)
}
if (
  contentBytes !== 0 || paddingBytes !== 0 || buffered.length !== 0 ||
  entryIndex !== expectedEntries.length || zeroBlocks < 2
) {
  throw new Error('archive has an incomplete payload or end marker')
}
