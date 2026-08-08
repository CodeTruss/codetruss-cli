import { readFile } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { renderLegacyMarkdown, renderMarkdown, renderPriorProfileMarkdown } from './receipt-markdown.js'
import { resolveReceipt } from './receipt-store.js'
import {
  loadSigningKey,
  normalizePublicKey,
  publicKeyFingerprint,
  sha256,
  verifyBytes,
} from './signing.js'
import type { Receipt } from './types.js'

/**
 * Checking a receipt against its signature, for the repository that wrote it and
 * for a third party that has only the files.
 */

/**
 * Every rendering this exact signed JSON could legitimately have produced.
 *
 * Rewording a disclosure must not invalidate receipts already on disk, so each
 * superseded wording stays reproducible for verification only. Shared by the
 * repository path and the third-party path so the two can never disagree about
 * which bytes the signature covers.
 */
export function acceptedMarkdownRenderings(receipt: Receipt): string[] {
  const profile = 'analysisProfile' in receipt.analyzers ? receipt.analyzers.analysisProfile : null
  return [
    renderMarkdown(receipt),
    // Superseded wordings are accepted only for the profile version that could
    // have produced them. A `local-registry-v2` receipt was never written by a
    // CLI that omitted SAST, so its Markdown must not be allowed to say so.
    ...(!profile ? [renderLegacyMarkdown(receipt)] : []),
    ...(profile?.id === 'local-registry-v1' ? [renderPriorProfileMarkdown(receipt)] : []),
  ]
}

/** Structural facts that must hold before any signature check means anything. */
function receiptStructureError(receipt: Receipt): string | null {
  if (receipt.git && ![receipt.git.baselineTree, receipt.git.finalTree].every((oid) => /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(oid))) {
    return 'receipt evidence tree object id is invalid'
  }
  if (receipt.policy && !/^[0-9a-f]{64}$/.test(receipt.policy.sha256)) {
    return 'receipt policy SHA-256 is invalid'
  }
  if (!receipt.evidence.publicKey || !receipt.evidence.signatureFile) return 'receipt is unsigned'
  return null
}

/**
 * A receipt names its own companion files, and a receipt handed over by a
 * stranger names them with bytes that stranger chose. Resolve them as plain
 * names beside the receipt so a hostile `signatureFile` cannot reach anywhere
 * else on the reader's disk.
 */
function companionPath(dir: string, name: string, label: string): string {
  if (name !== basename(name) || name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
    throw new Error(`receipt ${label} must be a plain file name beside the receipt`)
  }
  return join(dir, name)
}

/** One check over the bytes the signature covers. */
export interface ReceiptContentCheck {
  label: string
  status: 'ok' | 'failed' | 'skipped'
  /** Why it failed, or what could not be checked and why. */
  detail?: string
}

/**
 * Every check the signature makes possible, in order, against `publicKey`.
 *
 * This is the whole of what a signature can settle, and both verification paths
 * run exactly it: `verifyReceipt` throws on the first failure after deciding the
 * key is trusted, while the third-party path reports the list against the key
 * the receipt carries. Splitting the two would let one of them quietly check
 * less than the other claims.
 */
async function receiptContentChecks(
  jsonPath: string,
  receipt: Receipt,
  publicKey: string,
  /** False when a named companion may legitimately be absent, as in a published bundle. */
  requireCompanions: boolean,
): Promise<ReceiptContentCheck[]> {
  const dir = dirname(jsonPath)
  const checks: ReceiptContentCheck[] = []
  const read = async (name: string, label: string): Promise<Buffer | null> => {
    try {
      return await readFile(companionPath(dir, name, label))
    } catch (error) {
      if (!requireCompanions && (error as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw error
    }
  }

  const jsonBytes = await readFile(jsonPath)
  const signatureName = receipt.evidence.signatureFile as string
  const signatureBytes = await read(signatureName, 'signature file')
  const signatureLabel = 'ed25519 signature over the receipt JSON'
  if (!signatureBytes) {
    checks.push({ label: signatureLabel, status: 'failed', detail: `${signatureName} is not beside the receipt` })
  } else if (!verifyBytes(jsonBytes, publicKey, signatureBytes.toString('utf8').trim())) {
    checks.push({ label: signatureLabel, status: 'failed', detail: 'receipt signature does not match' })
  } else {
    checks.push({ label: signatureLabel, status: 'ok' })
  }

  const markdownName = `${receipt.sessionId}.md`
  const markdownBytes = await read(markdownName, 'Markdown receipt')
  const renderingLabel = 'Markdown rendering reproduces from the signed JSON'
  const digestLabel = 'Markdown SHA-256 matches the signed receipt'
  if (!markdownBytes) {
    checks.push({ label: renderingLabel, status: 'failed', detail: `${markdownName} is not beside the receipt` })
    checks.push({ label: digestLabel, status: 'skipped', detail: 'the Markdown rendering is not present' })
  } else {
    const markdown = markdownBytes.toString('utf8')
    const reproduced = acceptedMarkdownRenderings(receipt).includes(markdown)
    checks.push(reproduced
      ? { label: renderingLabel, status: 'ok' }
      : { label: renderingLabel, status: 'failed', detail: 'Markdown receipt does not match the signed JSON' })
    checks.push(sha256(markdown) === receipt.evidence.markdownSha256
      ? { label: digestLabel, status: 'ok' }
      : { label: digestLabel, status: 'failed', detail: 'Markdown receipt hash does not match' })
  }

  if (receipt.evidence.patchFile) {
    const patch = await read(receipt.evidence.patchFile, 'captured patch')
    const patchLabels = [
      'captured patch SHA-256 matches the recorded digest',
      'captured patch matches the signed diff hash',
      'captured patch byte count matches the signed receipt',
      'captured patch truncation metadata is consistent',
    ]
    if (!patch) {
      // Withholding the patch is a normal thing to do — it is the only part of
      // a receipt that quotes source. Its digest is inside the signed JSON, so
      // say what was not checked rather than pass over it in silence.
      checks.push({
        label: 'captured patch matches the signed receipt',
        status: 'skipped',
        detail: `${receipt.evidence.patchFile} was not published with this receipt; its signed SHA-256 is ${receipt.evidence.patchSha256 ?? '(not recorded)'}`,
      })
    } else {
      const totalBytes = receipt.diff.totalBytes ?? receipt.diff.bytes
      const conditions: Array<[boolean, string]> = [
        [sha256(patch) === receipt.evidence.patchSha256, 'captured patch hash does not match'],
        [sha256(patch) === receipt.diff.sha256, 'captured patch does not match the signed diff hash'],
        [patch.length === receipt.diff.bytes, 'captured patch byte count does not match the signed receipt'],
        [
          totalBytes >= receipt.diff.bytes && receipt.diff.truncated === (totalBytes > receipt.diff.bytes),
          'captured patch truncation metadata is inconsistent',
        ],
      ]
      for (const [index, [held, failure]] of conditions.entries()) {
        checks.push(held ? { label: patchLabels[index], status: 'ok' } : { label: patchLabels[index], status: 'failed', detail: failure })
      }
    }
  }
  return checks
}

export async function verifyReceipt(dir: string, id = 'latest', pinnedPublicKey?: string | string[]): Promise<Receipt> {
  const { receipt, jsonPath } = await resolveReceipt(dir, id)
  const structureError = receiptStructureError(receipt)
  if (structureError) throw new Error(structureError)
  // A repository may trust several signers (one per developer). The receipt is
  // valid when its embedded key is one of them, and the signature is then
  // checked against that exact key — so a teammate's receipt verifies without
  // anyone sharing a private key.
  const pins = Array.isArray(pinnedPublicKey) ? pinnedPublicKey : pinnedPublicKey ? [pinnedPublicKey] : []
  const trustedPublicKeys = pins.length > 0
    ? pins.map((pin) => normalizePublicKey(pin))
    : [(await loadSigningKey()).publicKey]
  const embeddedPublicKey = normalizePublicKey(receipt.evidence.publicKey as string)
  const embeddedFingerprint = publicKeyFingerprint(embeddedPublicKey)
  const trustedFingerprints = trustedPublicKeys.map((key) => publicKeyFingerprint(key))
  if (receipt.evidence.keyFingerprint !== embeddedFingerprint) throw new Error('receipt signing fingerprint does not match its public key')
  if (!trustedFingerprints.includes(embeddedFingerprint)) {
    // A receipt from another install is the expected case for anyone handed
    // evidence, not a malfunction. Refusing it without naming the supported way
    // to check it is what sent the first such reader off to write their own
    // verifier.
    throw new Error(
      `receipt signer ${embeddedFingerprint} does not match trusted key ${trustedFingerprints.join(', ')}; `
      + `this receipt was produced by another install — check it with codetruss verify-receipt ${join(dir, `${receipt.sessionId}.json`)} `
      + '[--public-key <file>]',
    )
  }
  const trustedPublicKey = trustedPublicKeys[trustedFingerprints.indexOf(embeddedFingerprint)]
  const checks = await receiptContentChecks(jsonPath, receipt, trustedPublicKey, true)
  const failed = checks.find((check) => check.status === 'failed')
  if (failed) throw new Error(failed.detail)
  return receipt
}

/**
 * What can be established about a receipt whose signer you have not pinned.
 *
 * Integrity and provenance are separate facts and this type keeps them
 * separate: `checks` settles whether the bytes are what was signed, and the
 * signer fingerprint is only ever a claim the receipt makes about itself.
 * Deciding whose key that is takes a key obtained from somewhere other than
 * this file, which is the caller's job.
 */
export interface ReceiptIntegrityResult {
  receipt: Receipt
  /** The key the receipt carries — evidence of nothing on its own. */
  signerFingerprint: string | null
  checks: ReceiptContentCheck[]
  /** True only when every check that could run held and none failed. */
  intact: boolean
}

/**
 * Verify a receipt file against the key inside it, trusting nothing on this
 * machine. Establishes integrity only; see `ReceiptIntegrityResult`.
 */
export async function verifyReceiptIntegrity(jsonPath: string): Promise<ReceiptIntegrityResult> {
  let receipt: Receipt
  try {
    receipt = JSON.parse(await readFile(jsonPath, 'utf8')) as Receipt
  } catch (error) {
    throw new Error(`could not read a CodeTruss receipt at ${jsonPath}: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!receipt || typeof receipt !== 'object' || typeof receipt.sessionId !== 'string' || !receipt.evidence) {
    throw new Error(`${jsonPath} is not a CodeTruss receipt`)
  }
  const structureError = receiptStructureError(receipt)
  if (structureError) {
    return { receipt, signerFingerprint: null, checks: [{ label: 'receipt is well-formed and signed', status: 'failed', detail: structureError }], intact: false }
  }
  let embeddedPublicKey: string
  try {
    embeddedPublicKey = normalizePublicKey(receipt.evidence.publicKey as string)
  } catch {
    return { receipt, signerFingerprint: null, checks: [{ label: 'receipt carries a usable public key', status: 'failed', detail: 'the embedded public key is not a readable key' }], intact: false }
  }
  const embeddedFingerprint = publicKeyFingerprint(embeddedPublicKey)
  const fingerprintLabel = 'recorded key fingerprint matches the embedded public key'
  const checks: ReceiptContentCheck[] = [
    receipt.evidence.keyFingerprint === embeddedFingerprint
      ? { label: fingerprintLabel, status: 'ok' }
      : { label: fingerprintLabel, status: 'failed', detail: 'receipt signing fingerprint does not match its public key' },
  ]
  try {
    checks.push(...await receiptContentChecks(jsonPath, receipt, embeddedPublicKey, false))
  } catch (error) {
    // Anything that stops a check from running leaves integrity unestablished,
    // which is the honest outcome — never a pass by omission.
    checks.push({
      label: 'the evidence this receipt names could be read',
      status: 'failed',
      detail: error instanceof Error ? error.message : String(error),
    })
  }
  return {
    receipt,
    signerFingerprint: embeddedFingerprint,
    checks,
    intact: !checks.some((check) => check.status === 'failed'),
  }
}
