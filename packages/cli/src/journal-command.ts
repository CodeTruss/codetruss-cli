import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import type { Writable } from 'node:stream'
import { receiptIds, verifyReceipt } from './receipt.js'
import { journalManifest, renderJournalHtml, type JournalEntry } from './receipt-journal-html.js'
import { loadSigningKey, signBytes } from './signing.js'
import type { CliConfig } from './types.js'

export interface JournalOptions {
  root: string
  receiptDirectory: string
  config: CliConfig
  out?: string
  since?: string
  until?: string
  includeOutput: boolean
  output: Writable
}

function dayBoundary(value: string, name: string, endOfDay: boolean): number {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error(`--${name} must be a date like 2026-08-14`)
  const time = Date.parse(`${value}T${endOfDay ? '23:59:59.999' : '00:00:00.000'}Z`)
  // Date.parse rolls impossible days over (2026-02-31 becomes March 3rd), so
  // an invalid date must be caught by the round trip, not by NaN.
  if (Number.isNaN(time) || !new Date(time).toISOString().startsWith(value)) {
    throw new Error(`--${name} is not a real date: ${value}`)
  }
  return time
}

/**
 * Build the shareable work journal from this repository's receipts. Receipts
 * that fail verification are excluded and named in the document — a journal
 * that silently dropped a receipt would be editing the record it exists to
 * keep.
 */
export async function runJournalCommand(options: JournalOptions): Promise<number> {
  const since = options.since ? dayBoundary(options.since, 'since', false) : undefined
  const until = options.until ? dayBoundary(options.until, 'until', true) : undefined
  if (since !== undefined && until !== undefined && since > until) {
    throw new Error('--since is after --until')
  }

  // Exclusion reasons render in the shareable document, and error messages
  // carry absolute local paths; the repository root becomes its basename
  // there, same as everywhere else in the journal.
  const scrub = (message: string) =>
    message.split(options.root).join(basename(options.root)).split(options.receiptDirectory).join('receipts')

  const entries: JournalEntry[] = []
  const excluded: { id: string; reason: string }[] = []
  for (const id of await receiptIds(options.receiptDirectory)) {
    let receipt
    try {
      receipt = await verifyReceipt(options.receiptDirectory, id, options.config.signing.publicKeys)
    } catch (error) {
      excluded.push({ id, reason: scrub(error instanceof Error ? error.message : String(error)) })
      continue
    }
    const createdAt = Date.parse(receipt.createdAt)
    if (since !== undefined && createdAt < since) continue
    if (until !== undefined && createdAt > until) continue
    // The journal embeds the complete verifiable set. A receipt whose
    // companion files are gone cannot be handed over whole, so it is excluded
    // and named like any other unverifiable entry.
    try {
      entries.push({
        receipt,
        signedJson: await readFile(join(options.receiptDirectory, `${id}.json`), 'utf8'),
        signature: (await readFile(join(options.receiptDirectory, `${id}.sig`), 'utf8')).trim(),
        markdown: await readFile(join(options.receiptDirectory, `${id}.md`), 'utf8'),
      })
    } catch (error) {
      excluded.push({ id, reason: scrub(error instanceof Error ? error.message : String(error)) })
    }
  }
  // receiptIds lists newest first; the journal reads oldest first.
  entries.reverse()

  const repo = basename(options.root)
  const generatedAt = new Date().toISOString()
  let signature
  try {
    const key = await loadSigningKey()
    const manifest = journalManifest({ repo, generatedAt, entries })
    signature = { manifest, signature: signBytes(manifest, key.privateKey), fingerprint: key.fingerprint }
  } catch {
    // No local signing key: the journal ships unsigned at the document level;
    // every embedded receipt stays individually signed.
  }

  const html = renderJournalHtml({
    repo,
    generatedAt,
    entries,
    excluded,
    publicKeys: options.config.signing.publicKeys,
    includeOutput: options.includeOutput,
    signature,
  })

  const outPath = options.out
    ? (isAbsolute(options.out) ? options.out : resolve(options.root, options.out))
    : join(options.root, '.codetruss', 'journal.html')
  await mkdir(dirname(outPath), { recursive: true })
  await writeFile(outPath, html)

  const range = entries.length
    ? `${entries[0].receipt.createdAt.slice(0, 10)} to ${entries.at(-1)!.receipt.createdAt.slice(0, 10)}`
    : 'no sessions'
  options.output.write(`Wrote work journal: ${outPath}\n`)
  options.output.write(`  ${entries.length} session(s), ${range}${excluded.length ? `, ${excluded.length} unverifiable receipt(s) excluded and disclosed` : ''}\n`)
  options.output.write('  Self-contained: attach the file to a deliverable; it opens in any browser and embeds the signed receipts for independent verification.\n')
  if (signature) {
    options.output.write(`  Journal manifest signed by ${signature.fingerprint}\n`)
  }
  return 0
}
