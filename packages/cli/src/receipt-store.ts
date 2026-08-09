import { chmod, mkdir, readFile, readdir, rename, unlink, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { renderMarkdown } from './receipt-markdown.js'
import { loadSigningKey, sha256, signBytes } from './signing.js'
import type { Receipt, SyncEnvelope } from './types.js'

/**
 * Receipts on disk: writing the signed set atomically, finding one again, and
 * producing the privacy-minimized copy an explicit hosted sync may carry.
 *
 * The redaction helpers live here rather than beside the renderer because they
 * exist for the sync envelope alone — a local receipt is never redacted.
 */

const SYNC_REDACTION = '[redacted unrelated path]'

function pathRelatedToChanges(path: string | undefined, changedPaths: string[]): boolean {
  if (!path) return false
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '')
  return changedPaths.some((changedPath) => (
    normalized === changedPath
    || normalized.startsWith(`${changedPath}/`)
    || changedPath.startsWith(`${normalized}/`)
  ))
}

function collectPotentialPaths(value: unknown, output: string[]): void {
  if (typeof value === 'string') {
    if (value.includes('/') || value.includes('\\') || /^[^\s]+\.[A-Za-z0-9]{1,12}$/.test(value)) output.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPotentialPaths(item, output)
    return
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) collectPotentialPaths(item, output)
  }
}

function pathVariants(path: string): string[] {
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '')
  const parts = normalized.split('/').filter(Boolean)
  return [...new Set([
    path,
    normalized,
    parts.length > 1 ? parts.slice(-2).join('/') : normalized,
  ].filter(Boolean))]
}

function redactKnownPaths(value: string, privatePaths: string[]): string {
  let redacted = value
  for (const path of privatePaths) redacted = redacted.replaceAll(path, SYNC_REDACTION)
  return redacted
}

async function writePrivateAtomic(path: string, value: string | Buffer): Promise<void> {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  try {
    await writeFile(temporary, value, { mode: 0o600, flag: 'wx' })
    await rename(temporary, path)
    await chmod(path, 0o600)
  } catch (error) {
    try { await unlink(temporary) } catch {}
    throw error
  }
}

export async function writeReceipt(dir: string, receipt: Receipt, patch: string | Buffer): Promise<{ json: string; markdown: string; signature: string }> {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  await chmod(dir, 0o700)
  const patchName = `${receipt.sessionId}.patch`
  const patchPath = join(dir, patchName)
  await writePrivateAtomic(patchPath, patch)
  receipt.evidence.patchFile = patchName
  receipt.evidence.patchSha256 = sha256(patch)
  const markdown = renderMarkdown(receipt)
  receipt.evidence.markdownSha256 = sha256(markdown)
  const key = await loadSigningKey(true)
  receipt.evidence.signatureFile = `${receipt.sessionId}.sig`
  receipt.evidence.publicKey = key.publicKey
  receipt.evidence.keyFingerprint = key.fingerprint
  const jsonText = `${JSON.stringify(receipt, null, 2)}\n`
  const signature = signBytes(jsonText, key.privateKey)
  const jsonPath = join(dir, `${receipt.sessionId}.json`)
  const markdownPath = join(dir, `${receipt.sessionId}.md`)
  const signaturePath = join(dir, `${receipt.sessionId}.sig`)
  await writePrivateAtomic(jsonPath, jsonText)
  await writePrivateAtomic(markdownPath, markdown)
  await writePrivateAtomic(signaturePath, `${signature}\n`)
  return { json: jsonPath, markdown: markdownPath, signature: signaturePath }
}

export async function receiptIds(dir: string): Promise<string[]> {
  try { return (await readdir(dir)).filter((name) => name.endsWith('.json')).map((name) => basename(name, '.json')).sort().reverse() } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error }
}

export async function resolveReceipt(dir: string, id = 'latest'): Promise<{ receipt: Receipt; jsonPath: string }> {
  const ids = await receiptIds(dir)
  const resolved = id === 'latest' ? ids[0] : id
  if (!resolved || !ids.includes(resolved)) throw new Error(`receipt ${id} not found`)
  const jsonPath = join(dir, `${resolved}.json`)
  return { receipt: JSON.parse(await readFile(jsonPath, 'utf8')) as Receipt, jsonPath }
}

/** Create a signed, privacy-minimized copy for an explicit hosted sync. */
export async function createSyncEnvelope(receipt: Receipt): Promise<SyncEnvelope> {
  const key = await loadSigningKey()
  const synced = structuredClone(receipt)
  const changedPaths = [...new Set(receipt.files.flatMap((file) => [file.path, file.oldPath])
    .filter((path): path is string => Boolean(path))
    .map((path) => path.replaceAll('\\', '/').replace(/^\.\//, '')))]
  const possiblePrivatePaths = [
    receipt.repoRoot,
    ...receipt.startDirtyFiles.filter((path) => !pathRelatedToChanges(path, changedPaths)),
    ...receipt.analyzers.findings
      .map((finding) => finding.filePath)
      .filter((path): path is string => Boolean(path) && !pathRelatedToChanges(path, changedPaths)),
    ...receipt.analyzers.passes.flatMap((pass) => pass.result.findings
      .map((finding) => finding.filePath)
      .filter((path): path is string => Boolean(path) && !pathRelatedToChanges(path, changedPaths))),
  ]
  for (const finding of receipt.analyzers.findings) collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  for (const finding of receipt.analyzers.suppressed ?? []) {
    if (finding.filePath && !pathRelatedToChanges(finding.filePath, changedPaths)) possiblePrivatePaths.push(finding.filePath)
    collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  }
  for (const pass of receipt.analyzers.passes) {
    for (const finding of pass.result.findings) collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  }
  const privatePaths = [...new Set(possiblePrivatePaths
    .filter((path) => !pathRelatedToChanges(path, changedPaths))
    .flatMap(pathVariants))]
    .sort((left, right) => right.length - left.length)

  synced.repoRoot = basename(receipt.repoRoot)
  synced.startDirtyFiles = synced.startDirtyFiles.filter((path) => pathRelatedToChanges(path, changedPaths))
  if (synced.agent) {
    synced.agent.command = synced.agent.command.length ? [basename(synced.agent.command[0])] : []
    delete synced.agent.startError
  }
  // Analyzer passes contain a second, whole-repository copy of every finding.
  // Sync only pass completion status and the separately filtered changed-file findings.
  synced.analyzers.passes = synced.analyzers.passes.map((pass) => {
    const result: Receipt['analyzers']['passes'][number]['result'] = {
      findings: [],
      complete: pass.result.complete,
    }
    if (pass.result.truncated !== undefined) result.truncated = pass.result.truncated
    return { id: pass.id, result }
  })
  const sanitizeFindings = (findings: Receipt['analyzers']['findings']): Receipt['analyzers']['findings'] => findings
    .filter((finding) => !finding.filePath || pathRelatedToChanges(finding.filePath, changedPaths))
    .map((finding) => {
      const sanitized = {
        ...finding,
        title: redactKnownPaths(finding.title, privatePaths),
        description: redactKnownPaths(finding.description, privatePaths),
      }
      if (finding.suggestion !== undefined) sanitized.suggestion = redactKnownPaths(finding.suggestion, privatePaths)
      // A dismissal reason is free text a developer wrote; it gets the same
      // path redaction as every other prose field on the way out.
      if (finding.suppression) {
        sanitized.suppression = { ...finding.suppression, reason: redactKnownPaths(finding.suppression.reason, privatePaths) }
      }
      delete sanitized.metadata
      // A suggested fix quotes real source lines and local paths. It stays on
      // the machine that produced it — the hosted copy never needs it.
      delete sanitized.fix
      return sanitized
    })
  synced.analyzers.findings = sanitizeFindings(synced.analyzers.findings)
  if (synced.analyzers.suppressed) {
    const suppressed = sanitizeFindings(synced.analyzers.suppressed)
    if (suppressed.length) synced.analyzers.suppressed = suppressed
    else delete synced.analyzers.suppressed
  }
  if (synced.analyzers.rejectedSuppressions) {
    // `path:line`, so the path is everything before the final colon.
    const sites = synced.analyzers.rejectedSuppressions
      .filter((site) => pathRelatedToChanges(site.slice(0, site.lastIndexOf(':')), changedPaths))
    if (sites.length) synced.analyzers.rejectedSuppressions = sites
    else delete synced.analyzers.rejectedSuppressions
  }
  synced.verifications = synced.verifications.map((item) => ({ ...item, command: '[redacted for sync]', output: '' }))
  // The producer's signing identity stays exactly as the receipt recorded it;
  // the exporting key signs the envelope and is named separately. Overwriting
  // the producer fields here (the old behavior) relabeled a teammate's receipt
  // as whoever ran `codetruss sync`.
  const producer = receipt.evidence.publicKey && receipt.evidence.keyFingerprint
    ? { publicKey: receipt.evidence.publicKey, keyFingerprint: receipt.evidence.keyFingerprint }
    : { publicKey: key.publicKey, keyFingerprint: key.fingerprint }
  synced.evidence = {
    patchSha256: receipt.evidence.patchSha256,
    ...producer,
    exporter: { publicKey: key.publicKey, keyFingerprint: key.fingerprint },
  }
  synced.coverageNotes = [
    ...synced.coverageNotes,
    'Hosted sync copy redacted the absolute repository path, unrelated dirty paths, agent arguments/start error, verification commands/output, duplicate whole-repository analyzer finding bodies, unrelated analyzer paths/metadata, suggested-fix bodies, and local evidence filenames.',
  ]
  const signedReceipt = `${JSON.stringify(synced, null, 2)}\n`
  return { signedReceipt, signature: signBytes(signedReceipt, key.privateKey) }
}

