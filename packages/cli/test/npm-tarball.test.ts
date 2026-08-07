import { createSign, generateKeyPairSync } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { readTarballMembers, verifyRegistrySignature } from '../scripts/npm-tarball.mjs'

/**
 * The two primitives the release-time attestation rests on.
 *
 * `attest-grammar-sources.mjs` itself needs the network, so it is not a test —
 * but nothing about reading a tarball or checking a signature does, and those
 * are the parts where a quiet bug would turn the attestation into a formality
 * that passes on anything.
 */
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
/** A real npm tarball this repository publishes, used as the fixture. */
const cliTarball = join(repoRoot, 'public', 'downloads', 'codetruss-cli-latest.tgz')

describe('reading an npm tarball', () => {
  it('returns the members of a real published package', async () => {
    const members = readTarballMembers(await readFile(cliTarball))
    const manifest = members.get('package/package.json')
    expect(manifest).toBeInstanceOf(Buffer)
    expect(JSON.parse(manifest!.toString('utf8')).name).toBe('@codetruss/cli')
    // Every member is a file the archive actually carries, with its real length.
    expect(members.get('package/dist/cli.cjs')!.length).toBeGreaterThan(1_000)
    expect(members.get('package/does-not-exist')).toBeUndefined()
  })

  it('refuses an archive whose headers do not check out rather than guessing', async () => {
    // Corrupt the length field of the first header. A reader that trusted it
    // would resynchronise onto file content, read a data block as a header, and
    // hand back whatever it found under whatever name it thought it had.
    const { gunzipSync, gzipSync } = await import('node:zlib')
    const tar = Buffer.from(gunzipSync(await readFile(cliTarball)))
    tar.write('00000000777', 124, 11, 'ascii')
    expect(() => readTarballMembers(gzipSync(tar))).toThrow(/bad checksum/)
  })
})

describe('verifying a registry signature', () => {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const keyid = 'SHA256:test'
  const keys = [{
    keyid,
    keytype: 'ecdsa-sha2-nistp256',
    scheme: 'ecdsa-sha2-nistp256',
    key: keyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
  }]
  const name = 'web-tree-sitter'
  const version = '0.22.6'
  const integrity = 'sha512-AAAA=='
  const sign = (message: string) => createSign('SHA256')
    .update(message)
    .end()
    .sign(keyPair.privateKey)
    .toString('base64')

  it('accepts a signature over exactly name@version:integrity', () => {
    const signature = { keyid, sig: sign(`${name}@${version}:${integrity}`) }
    expect(() => verifyRegistrySignature({ name, version, integrity, signature, keys })).not.toThrow()
  })

  it('rejects a signature over a different tarball digest', () => {
    // The attack the signature exists to stop: a mirror serving the right
    // version with someone else's bytes. The digest is inside the signed
    // message, so a substituted one cannot carry the old signature.
    const signature = { keyid, sig: sign(`${name}@${version}:sha512-BBBB==`) }
    expect(() => verifyRegistrySignature({ name, version, integrity, signature, keys }))
      .toThrow(/does not verify/)
  })

  it('rejects a key the registry never published', () => {
    const signature = { keyid: 'SHA256:unknown', sig: sign(`${name}@${version}:${integrity}`) }
    expect(() => verifyRegistrySignature({ name, version, integrity, signature, keys }))
      .toThrow(/no published key/)
  })
})
