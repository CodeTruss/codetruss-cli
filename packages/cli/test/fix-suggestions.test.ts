import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { AnalyzerFinding, FindingFix } from '@codetruss/analyzer-engine'
import { afterEach, describe, expect, it } from 'vitest'
import { FIX_DISCLAIMER, suggestedFixLines, topFixSuggestion } from '../src/fix-suggestions.js'
import { createSyncEnvelope, renderMarkdown, verifyReceipt, writeReceipt } from '../src/receipt.js'
import { PRE_SUGGESTION_RECEIPT_MARKDOWN, fixtureFindings, fixtureReceipt } from './fix-suggestion-fixture.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY
const roots: string[] = []

afterEach(async () => {
  if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY
  else process.env.CODETRUSS_SIGNING_KEY = originalKey
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

function fix(overrides: Partial<FindingFix> = {}): FindingFix {
  return {
    description: 'Read the credential from `AWS_KEY` at runtime.',
    kind: 'diff',
    language: 'diff',
    content: '--- a/src/config.ts\n+++ b/src/config.ts\n@@ -12 +12 @@\n-const awsKey = "<masked>"\n+const awsKey = process.env.AWS_KEY\n',
    safetyNote: 'Rotate this credential first — it is already in Git history.',
    ...overrides,
  }
}

function withFixes(): AnalyzerFinding[] {
  const [secret, lockfile] = fixtureFindings()
  return [
    { ...lockfile, fix: fix({ kind: 'snippet', language: 'sh', content: 'pnpm install --lockfile-only\n', description: 'Generate and commit pnpm-lock.yaml with pnpm.', safetyNote: 'Review the generated lockfile before committing.' }) },
    { ...secret, fix: fix() },
  ]
}

describe('suggested fixes in the signed receipt', () => {
  it('renders nothing at all when no finding carries a fix', () => {
    expect(suggestedFixLines(fixtureFindings())).toEqual([])
  })

  it('reproduces the exact pre-suggestion Markdown for a fix-free receipt', () => {
    // Backward verification: the golden was produced by the renderer that
    // shipped before fixes existed. Any byte drift here invalidates every
    // receipt already signed on disk.
    expect(renderMarkdown(fixtureReceipt(fixtureFindings()))).toBe(PRE_SUGGESTION_RECEIPT_MARKDOWN)
  })

  it('verifies a receipt written before fixes existed and one written with them', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-fix-verify-'))
    roots.push(root)
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')

    const withoutFixes = fixtureReceipt(fixtureFindings())
    const dir = join(root, 'receipts')
    await writeReceipt(dir, withoutFixes, 'diff evidence')
    await expect(verifyReceipt(dir, withoutFixes.sessionId)).resolves.toMatchObject({ verdict: 'REVIEW_REQUIRED' })
    expect(await readFile(join(dir, `${withoutFixes.sessionId}.md`), 'utf8')).toBe(PRE_SUGGESTION_RECEIPT_MARKDOWN)

    const suggested = { ...fixtureReceipt(withFixes()), sessionId: '20260712T210000123Z-suggested' }
    await writeReceipt(dir, suggested, 'diff evidence')
    await expect(verifyReceipt(dir, suggested.sessionId)).resolves.toMatchObject({ verdict: 'REVIEW_REQUIRED' })
  })

  it('shows each suggestion as a fenced block with its location and safety note', () => {
    const markdown = renderMarkdown(fixtureReceipt(withFixes()))
    expect(markdown).toContain('## Suggested fixes (2)')
    // Highest severity first, regardless of finding order.
    expect(markdown.indexOf('### HIGH —')).toBeLessThan(markdown.indexOf('### MEDIUM —'))
    expect(markdown).toContain('### HIGH — Possible AWS access key committed in config.ts (`src/config.ts:12`)')
    expect(markdown).toContain('```diff\n--- a/src/config.ts')
    expect(markdown).toContain('```sh\npnpm install --lockfile-only\n```')
    expect(markdown).toContain('Before applying: Rotate this credential first')
  })

  it('never presents a suggestion as applied, automatic, or mandatory', () => {
    const markdown = renderMarkdown(fixtureReceipt(withFixes()))
    expect(markdown).toContain(FIX_DISCLAIMER)
    expect(FIX_DISCLAIMER).toMatch(/did not apply, write, or run/)
    for (const forbidden of [
      /CodeTruss (?:has )?applied/i,
      /automatically (?:applied|fixed|corrected)/i,
      /(?:fix|change) (?:was|has been) applied/i,
      /you must apply/i,
      /required fix/i,
    ]) {
      expect(markdown).not.toMatch(forbidden)
    }
  })

  it('widens the fence so a Markdown starter block cannot end it early', () => {
    const starter = '# Project\n\n## Quick start\n\n```sh\npnpm install\n```\n'
    const [finding] = fixtureFindings()
    const markdown = renderMarkdown(fixtureReceipt([
      { ...finding, fix: fix({ kind: 'snippet', language: 'markdown', content: starter }) },
    ]))
    expect(markdown).toContain('````markdown\n# Project')
    expect(markdown).toContain('```sh\npnpm install\n```\n````')
  })

  it('keeps suggested fixes off the hosted sync copy', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-fix-sync-'))
    roots.push(root)
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixtureReceipt(withFixes())
    receipt.files = [{ path: 'src/config.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 1, deletions: 1 }]
    await writeReceipt(join(root, 'receipts'), receipt, 'diff evidence')
    const envelope = await createSyncEnvelope(receipt)
    const synced = JSON.parse(envelope.signedReceipt) as { analyzers: { findings: AnalyzerFinding[] }; coverageNotes: string[] }

    expect(synced.analyzers.findings.length).toBeGreaterThan(0)
    for (const finding of synced.analyzers.findings) expect(finding).not.toHaveProperty('fix')
    expect(envelope.signedReceipt).not.toContain('process.env.AWS_KEY')
    expect(synced.coverageNotes.at(-1)).toContain('suggested-fix bodies')
    // The local receipt keeps everything the sync copy dropped.
    expect(receipt.analyzers.findings[1].fix).toBeDefined()
  })
})

describe('the agent-facing Stop summary line', () => {
  it('returns nothing when no finding carries a fix', () => {
    expect(topFixSuggestion(fixtureFindings())).toBeUndefined()
  })

  it('carries exactly the highest-severity suggestion, framed as not applied', () => {
    const summary = topFixSuggestion(withFixes())
    expect(summary).toBeDefined()
    expect(summary).toContain('Suggested fix (NOT applied — review before using) for HIGH')
    expect(summary).toContain('"Possible AWS access key committed in config.ts" at src/config.ts:12')
    expect(summary).toContain('Read the credential from `AWS_KEY` at runtime.')
    expect(summary).toContain('Rotate this credential first')
    // One suggestion, not a digest of every finding.
    expect(summary).not.toContain('No lockfile committed')
  })

  it('stays inside the hook result per-reason character bound', () => {
    const [finding] = fixtureFindings()
    const summary = topFixSuggestion([{ ...finding, fix: fix({ safetyNote: 'x'.repeat(5_000) }) }])
    expect(summary!.length).toBeLessThanOrEqual(2_000)
  })
})
