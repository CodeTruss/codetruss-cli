import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { renderMarkdown, verifyReceipt, verifyReceiptIntegrity, writeReceipt } from '../src/receipt.js'
import { runVerifyReceiptCommand } from '../src/verify-receipt-command.js'
import { loadSigningKey, sha256 } from '../src/signing.js'
import { LOCAL_ANALYSIS_PROFILE, type Receipt } from '../src/types.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY
afterEach(() => { if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY; else process.env.CODETRUSS_SIGNING_KEY = originalKey })

/**
 * The rendering of the fixture below, one digest per profile version.
 *
 * These are recomputed only when the fixture itself changes — never to
 * accommodate a reworded profile block, which is the exact edit they exist to
 * stop. A superseded block is the wording some receipt on someone else's disk
 * was signed against; changing it silently un-verifies that receipt.
 */
const FROZEN_MARKDOWN_SHA256: Record<string, string> = {
  'local-registry-v1': '928da3c48ba873b8234573eea6510b0dc80b32ff12d822f51a68a23943097597',
  'local-registry-v2': '113d62dee72cce21ca004ce3bf748cc8ff08a8bcceacfdc65100c5b21487dea2',
  'local-registry-v3': 'f38a8bde572f2c83ddcd76e167762acc80c0e603d2e45a43d3b4dd86aef1579a',
  'local-registry-v4': '288de3e266dd208735854a35ec467caa44307414121020e062eec58e808cb66b',
  'local-registry-v5': '6ae337ce26c127531cb97aa5418f64fa2681898228c3a53ba25eb2777b9e1703',
}

/** Every analysis profile whose Markdown wording is frozen inside signed receipts. */
const FROZEN_PROFILES = [
  { id: 'local-registry-v1', profile: { id: 'local-registry-v1', omittedPasses: ['graph', 'sast'], scoreStatus: 'not-computed' } },
  { id: 'local-registry-v2', profile: { id: 'local-registry-v2', omittedPasses: ['graph'], localPasses: ['local-sast'], scoreStatus: 'not-computed' } },
  { id: 'local-registry-v3', profile: { id: 'local-registry-v3', omittedPasses: ['graph'], localPasses: ['local-sast'], scoreStatus: 'not-computed' } },
  { id: 'local-registry-v4', profile: { id: 'local-registry-v4', omittedPasses: ['graph'], localPasses: ['local-sast'], scoreStatus: 'not-computed' } },
  { id: 'local-registry-v5', profile: LOCAL_ANALYSIS_PROFILE },
] as const

function fixture(profile: unknown = LOCAL_ANALYSIS_PROFILE, patch = 'diff evidence'): Receipt {
  const now = new Date('2026-07-12T21:00:00.123Z')
  return {
    receiptVersion: 1, sessionId: '20260712T210000123Z-abcdef', createdAt: now.toISOString(), finishedAt: now.toISOString(), durationMs: 0,
    mode: 'review', task: 'third-party receipt', repoRoot: '/repo', startCommit: 'abc', endCommit: 'abc',
    git: { baselineTree: 'a'.repeat(40), finalTree: 'b'.repeat(40) }, policy: { sha256: 'c'.repeat(64) }, startDirty: false, startDirtyFiles: [],
    scope: { allow: ['src/**'], deny: [] }, files: [], diff: {
      sha256: createHash('sha256').update(patch).digest('hex'),
      bytes: Buffer.byteLength(patch),
      totalBytes: Buffer.byteLength(patch),
      truncated: false,
    },
    analyzers: {
      passes: [], findings: [], index: { totalLoc: 0, languages: {}, primaryLanguage: null },
      ...(profile ? { analysisProfile: profile } : { scores: { health: 100, debt: 100, architecture: 100, security: 100, docs: 100 } }),
    } as Receipt['analyzers'],
    verifications: [], coverageNotes: ['local'], verdict: 'PASS', reasons: ['no changes'], evidence: {},
  }
}

/**
 * A receipt produced somewhere else: signed by a key that is not the one this
 * machine holds, and delivered as bytes on disk.
 */
async function foreignReceipt(profile: unknown = LOCAL_ANALYSIS_PROFILE): Promise<{
  dir: string
  jsonPath: string
  receipt: Receipt
  signerPublicKeyPath: string
  signerFingerprint: string
}> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-foreign-'))
  const dir = join(root, 'delivered')
  process.env.CODETRUSS_SIGNING_KEY = join(root, 'their-signing.pem')
  const receipt = fixture(profile)
  const paths = await writeReceipt(dir, receipt, 'diff evidence')
  const signer = await loadSigningKey()
  const signerPublicKeyPath = join(root, 'their-public.pem')
  await writeFile(signerPublicKeyPath, signer.publicKey)
  // The reader's own install holds a different key, as any real reader's would.
  process.env.CODETRUSS_SIGNING_KEY = join(root, 'my-signing.pem')
  await loadSigningKey(true)
  return { dir, jsonPath: paths.json, receipt, signerPublicKeyPath, signerFingerprint: signer.fingerprint }
}

function capture(): { write: (text: string) => void; text: () => string } {
  const chunks: string[] = []
  return { write: (text) => { chunks.push(text) }, text: () => chunks.join('') }
}

describe('verifying a receipt you did not produce', () => {
  it('establishes integrity from the receipt alone and refuses to call that verified', async () => {
    const { jsonPath, signerFingerprint } = await foreignReceipt()
    const output = capture()

    const code = await runVerifyReceiptCommand(jsonPath, [], output.write)

    expect(code).toBe(1)
    expect(output.text()).toContain('integrity: ESTABLISHED')
    expect(output.text()).toContain('provenance: NOT ESTABLISHED')
    expect(output.text()).toContain(signerFingerprint)
    // The one sentence that keeps the two claims apart.
    expect(output.text()).toContain('It does not prove who that someone is')
    expect(output.text()).toContain('--public-key')
    // A green word, or a green exit, would let a reader stop reading here.
    expect(output.text()).not.toContain('VERIFIED')
  })

  it('establishes provenance only against a key supplied out of band', async () => {
    const { jsonPath, signerPublicKeyPath } = await foreignReceipt()
    const output = capture()

    const code = await runVerifyReceiptCommand(jsonPath, [signerPublicKeyPath], output.write)

    expect(code).toBe(0)
    expect(output.text()).toContain('integrity: ESTABLISHED')
    expect(output.text()).toContain('provenance: ESTABLISHED')
    expect(output.text()).toContain(signerPublicKeyPath)
    // Even both claims together stop short of the run having happened.
    expect(output.text()).toContain('Neither proves the analysis described here actually ran')
  })

  it('accepts the delivered directory as well as the receipt file', async () => {
    const { dir, signerPublicKeyPath } = await foreignReceipt()
    const output = capture()

    expect(await runVerifyReceiptCommand(dir, [signerPublicKeyPath], output.write)).toBe(0)
    expect(output.text()).toContain('integrity: ESTABLISHED')
  })

  it('reports a tampered receipt as not intact and does not attribute it to anyone', async () => {
    const { jsonPath, dir, receipt, signerPublicKeyPath } = await foreignReceipt()
    const markdownPath = join(dir, `${receipt.sessionId}.md`)
    await writeFile(markdownPath, `${await readFile(markdownPath, 'utf8')}\n- and nothing was found\n`)
    const output = capture()

    const code = await runVerifyReceiptCommand(jsonPath, [signerPublicKeyPath], output.write)

    expect(code).toBe(2)
    expect(output.text()).toContain('integrity: NOT ESTABLISHED')
    expect(output.text()).toContain('FAIL  Markdown rendering reproduces from the signed JSON')
    // A key match must never print as provenance over bytes that failed.
    expect(output.text()).toContain('provenance: NOT CHECKED')
    expect(output.text()).not.toContain('provenance: ESTABLISHED')
    expect(output.text()).toContain('Do not rely on this receipt')
  })

  it('reports an edited-and-resigned receipt as intact but not from the key you trust', async () => {
    // The forgery this separation exists to catch: internally consistent bytes,
    // a perfectly valid signature, and a signer nobody asked you to trust.
    const { jsonPath, dir, receipt, signerPublicKeyPath } = await foreignReceipt()
    const forged = JSON.parse(await readFile(jsonPath, 'utf8')) as Receipt
    forged.verdict = 'PASS'
    forged.reasons = ['nothing to report']
    const attacker = generateKeyPairSync('ed25519')
    forged.evidence.publicKey = attacker.publicKey.export({ type: 'spki', format: 'pem' }).toString()
    forged.evidence.keyFingerprint = sha256(attacker.publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16)
    forged.evidence.markdownSha256 = sha256(renderMarkdown(forged))
    const forgedJson = `${JSON.stringify(forged, null, 2)}\n`
    await writeFile(jsonPath, forgedJson)
    await writeFile(join(dir, `${receipt.sessionId}.md`), renderMarkdown(forged))
    await writeFile(join(dir, `${receipt.sessionId}.sig`), `${sign(null, Buffer.from(forgedJson), attacker.privateKey).toString('base64')}\n`)
    const output = capture()

    const code = await runVerifyReceiptCommand(jsonPath, [signerPublicKeyPath], output.write)

    expect(code).toBe(1)
    expect(output.text()).toContain('integrity: ESTABLISHED')
    expect(output.text()).toContain('provenance: NOT ESTABLISHED')
    expect(output.text()).toContain('is not the key you supplied')
  })

  it('says what could not be checked when the patch is withheld, rather than passing over it', async () => {
    const { jsonPath, dir, receipt, signerPublicKeyPath } = await foreignReceipt()
    await rm(join(dir, `${receipt.sessionId}.patch`))
    const output = capture()

    const code = await runVerifyReceiptCommand(jsonPath, [signerPublicKeyPath], output.write)

    expect(code).toBe(0)
    expect(output.text()).toContain('skip  captured patch matches the signed receipt')
    expect(output.text()).toContain('was not published with this receipt; its signed SHA-256 is')
    // The headline must carry the hole in the evidence, not only the check list.
    expect(output.text()).toContain('integrity: ESTABLISHED — over what was published; 1 recorded piece of evidence is absent and unchecked')
  })

  it('will not follow a companion file name that points outside the delivered receipt', async () => {
    const { jsonPath } = await foreignReceipt()
    const hostile = JSON.parse(await readFile(jsonPath, 'utf8')) as Receipt
    hostile.evidence.signatureFile = '../../../../etc/passwd'
    await writeFile(jsonPath, `${JSON.stringify(hostile, null, 2)}\n`)

    const result = await verifyReceiptIntegrity(jsonPath)

    expect(result.intact).toBe(false)
    expect(result.checks.some((check) => check.detail?.includes('plain file name beside the receipt'))).toBe(true)
  })

  it('refuses a receipt whose recorded fingerprint does not match its own embedded key', async () => {
    const { jsonPath } = await foreignReceipt()
    const edited = JSON.parse(await readFile(jsonPath, 'utf8')) as Receipt
    edited.evidence.keyFingerprint = '0'.repeat(16)
    await writeFile(jsonPath, `${JSON.stringify(edited, null, 2)}\n`)
    const output = capture()

    expect(await runVerifyReceiptCommand(jsonPath, [], output.write)).toBe(2)
    expect(output.text()).toContain('FAIL  recorded key fingerprint matches the embedded public key')
  })
})

describe('the repository path is unchanged', () => {
  it('still refuses a foreign receipt, and now names the command that can check it', async () => {
    const { dir, receipt } = await foreignReceipt()

    await expect(verifyReceipt(dir, receipt.sessionId)).rejects.toThrow(/does not match trusted key/)
    await expect(verifyReceipt(dir, receipt.sessionId)).rejects.toThrow(/codetruss verify-receipt/)
  })

  it('still verifies a receipt the repository does trust', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-trusted-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixture()
    await writeReceipt(dir, receipt, 'diff evidence')
    const key = await loadSigningKey()

    await expect(verifyReceipt(dir, receipt.sessionId, [key.publicKey])).resolves.toMatchObject({ verdict: 'PASS' })
  })
})

describe('frozen profile renderings', () => {
  it.each(FROZEN_PROFILES)('verifies a $id receipt through both paths', async ({ profile }) => {
    const { dir, jsonPath, receipt, signerPublicKeyPath } = await foreignReceipt(profile)

    // The trusted path, given the signer's key, and the third-party path must
    // accept exactly the same signed Markdown bytes.
    await expect(verifyReceipt(dir, receipt.sessionId, [await readFile(signerPublicKeyPath, 'utf8')]))
      .resolves.toMatchObject({ verdict: 'PASS' })
    const result = await verifyReceiptIntegrity(jsonPath)
    expect(result.intact).toBe(true)
    expect(result.checks.filter((check) => check.status === 'failed')).toEqual([])
  })

  it.each(FROZEN_PROFILES)('renders $id to the exact bytes its signature covers', async ({ profile }) => {
    const { dir, receipt } = await foreignReceipt(profile)
    const markdown = await readFile(join(dir, `${receipt.sessionId}.md`), 'utf8')

    // The digest of the rendering, pinned. A superseded profile block may never
    // be reworded: receipts already signed against it would stop verifying.
    expect(sha256(markdown)).toBe(FROZEN_MARKDOWN_SHA256[profile.id])
  })

  it('accepts a legacy score-bearing receipt through the third-party path', async () => {
    const { jsonPath } = await foreignReceipt(null)

    await expect(verifyReceiptIntegrity(jsonPath)).resolves.toMatchObject({ intact: true })
  })
})
