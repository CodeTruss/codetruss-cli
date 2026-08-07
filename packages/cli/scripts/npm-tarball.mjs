/**
 * Reading and authenticating an npm tarball, without adding a dependency.
 *
 * Used by `attest-grammar-sources.mjs` to obtain a grammar pack's upstream bytes
 * from something other than the release machine's `node_modules`. A tar reader
 * and an ECDSA verify are about eighty lines between them; a package that did
 * this for us would be one more thing on the release machine that the check is
 * supposed to be independent of.
 */
import { createHash, createPublicKey, createVerify } from 'node:crypto'
import { gunzipSync } from 'node:zlib'

const BLOCK = 512

function trimmed(header, offset, length) {
  const raw = header.subarray(offset, offset + length).toString('utf8')
  const end = raw.indexOf('\0')
  return (end === -1 ? raw : raw.slice(0, end)).trim()
}

function octal(header, offset, length) {
  const text = trimmed(header, offset, length)
  return text === '' ? 0 : Number.parseInt(text, 8)
}

/**
 * The header's own checksum, so a misparse is loud.
 *
 * Every failure mode of this reader has to end in "member not found" or "digest
 * mismatch", never in silently returning the wrong bytes. Checking the checksum
 * is what makes a wrong offset stop immediately instead of walking into the
 * middle of a file and calling it a header.
 */
function headerChecksumOk(header) {
  const recorded = octal(header, 148, 8)
  let sum = 0
  for (let index = 0; index < BLOCK; index += 1) {
    sum += index >= 148 && index < 156 ? 0x20 : header[index]
  }
  return sum === recorded
}

/**
 * Every regular file in a gzipped tar, keyed by its full path.
 *
 * Handles the ustar name/prefix split and GNU long names. Pax extended headers
 * are skipped rather than interpreted: an npm package whose paths need them
 * would resolve to the truncated ustar name here, the caller would not find the
 * member it asked for, and the attestation fails closed instead of comparing
 * against the wrong file.
 */
export function readTarballMembers(tarball) {
  const tar = Buffer.from(gunzipSync(tarball))
  const members = new Map()
  let longName
  let offset = 0

  while (offset + BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK)
    // Two zero blocks end the archive; one is enough to stop reading.
    if (header.every((byte) => byte === 0)) break
    if (!headerChecksumOk(header)) throw new Error(`tar header at offset ${offset} has a bad checksum`)

    const size = octal(header, 124, 12)
    const type = String.fromCharCode(header[156] || 0x30)
    const name = longName ?? trimmed(header, 0, 100)
    const prefix = trimmed(header, 345, 155)
    longName = undefined

    offset += BLOCK
    const body = tar.subarray(offset, offset + size)
    offset += Math.ceil(size / BLOCK) * BLOCK

    if (type === 'L') {
      longName = body.toString('utf8').replace(/\0[\s\S]*$/, '')
      continue
    }
    if (type !== '0' && type !== '\0') continue
    members.set(prefix ? `${prefix}/${name}` : name, Buffer.from(body))
  }
  return members
}

/** The `sha512-…` form npm and pnpm both record, for a set of bytes. */
export function subresourceIntegrity(bytes) {
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`
}

/**
 * The registry's signature over `name@version:integrity`.
 *
 * This is what makes the tarball's digest something other than a number the
 * same server chose: npm signs the association between a version and its
 * tarball digest with a key published at `/-/npm/v1/keys`, so a registry mirror
 * or a proxy cannot rewrite one without the other.
 */
export function verifyRegistrySignature({ name, version, integrity, signature, keys }) {
  const key = keys.find((candidate) => candidate.keyid === signature.keyid)
  if (!key) throw new Error(`registry has no published key ${signature.keyid} for ${name}@${version}`)
  if (key.keytype !== 'ecdsa-sha2-nistp256' || key.scheme !== 'ecdsa-sha2-nistp256') {
    throw new Error(`unsupported registry key type ${key.keytype}/${key.scheme}`)
  }
  const publicKey = createPublicKey({ key: Buffer.from(key.key, 'base64'), format: 'der', type: 'spki' })
  const verified = createVerify('SHA256')
    .update(`${name}@${version}:${integrity}`)
    .end()
    .verify(publicKey, Buffer.from(signature.sig, 'base64'))
  if (!verified) throw new Error(`registry signature for ${name}@${version} does not verify`)
}
