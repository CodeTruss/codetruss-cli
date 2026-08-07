import { createHash } from 'node:crypto'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import type { AnalyzerFinding, RepoIndex } from '@codetruss/analyzer-engine'
import { analyzerReceipt, computeVerdict } from '../src/analysis.js'
import { createSyncEnvelope, newSessionId, renderMarkdown, verifyReceipt, writeReceipt } from '../src/receipt.js'
import { LOCAL_ANALYSIS_PROFILE, type ChangedFile, type Receipt } from '../src/types.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY
afterEach(() => { if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY; else process.env.CODETRUSS_SIGNING_KEY = originalKey })

function finding(overrides: Partial<AnalyzerFinding> = {}): AnalyzerFinding {
  return {
    analyzerId: 'secrets',
    category: 'SECURITY_HYGIENE',
    severity: 'HIGH',
    title: 'Possible Database URL with credentials committed in db.ts',
    description: 'Line 4 of src/db.ts appears to contain a credential.',
    filePath: 'src/db.ts',
    line: 4,
    impactScore: 95,
    ...overrides,
  }
}

function dismissed(reason: string, overrides: Partial<AnalyzerFinding> = {}): AnalyzerFinding {
  return finding({ ...overrides, suppression: { reason, markerLine: 4, applied: true } })
}

const changedFile: ChangedFile = {
  path: 'src/db.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 1, deletions: 0,
}

function verdictInput(findings: AnalyzerFinding[]) {
  return { verifications: [], files: [changedFile], startDirty: false, findings }
}

function analysis(findings: AnalyzerFinding[]) {
  return {
    findings,
    passes: [{ id: 'secrets', result: { findings, complete: true } }],
    index: { totalLoc: 10, languages: { TypeScript: 10 }, primaryLanguage: 'TypeScript' } as unknown as RepoIndex,
  }
}

function receiptFixture(root: string, patch = 'diff evidence'): Receipt {
  const now = new Date('2026-08-06T09:00:00.123Z')
  return {
    receiptVersion: 1, sessionId: newSessionId(now), createdAt: now.toISOString(), finishedAt: now.toISOString(), durationMs: 0,
    mode: 'review', task: 'suppression receipt', repoRoot: root, startCommit: 'abc', endCommit: 'abc',
    git: { baselineTree: 'a'.repeat(40), finalTree: 'b'.repeat(40) }, policy: { sha256: 'c'.repeat(64) },
    startDirty: false, startDirtyFiles: [],
    scope: { allow: ['src/**'], deny: [] },
    files: [changedFile],
    diff: {
      sha256: createHash('sha256').update(patch).digest('hex'),
      bytes: Buffer.byteLength(patch),
      totalBytes: Buffer.byteLength(patch),
      truncated: false,
    },
    analyzers: { passes: [], findings: [], analysisProfile: LOCAL_ANALYSIS_PROFILE, index: { totalLoc: 0, languages: {}, primaryLanguage: null } },
    verifications: [], coverageNotes: ['local'], verdict: 'PASS', reasons: ['no changes'], evidence: {},
  }
}

describe('a dismissed finding stops gating', () => {
  it('lets a verdict pass over a dismissed high-severity security finding, and says so', () => {
    const outcome = computeVerdict(verdictInput([dismissed('rotated; kept until the migration window closes')]))

    expect(outcome.verdict).toBe('PASS')
    expect(outcome.reasons).toContain(
      '1 finding(s) on changed files were dismissed by an inline codetruss-ignore comment and are listed with their reasons on this receipt',
    )
  })

  it('still fails on the identical finding when nothing dismissed it', () => {
    const outcome = computeVerdict(verdictInput([finding()]))

    expect(outcome.verdict).toBe('FAILED')
    expect(outcome.reasons[0]).toContain('high/critical security or dependency finding')
  })

  it('still fails when the marker gave no reason, because that dismisses nothing', () => {
    const outcome = computeVerdict(verdictInput([
      finding({ suppression: { reason: '', markerLine: 4, applied: false } }),
    ]))

    expect(outcome.verdict).toBe('FAILED')
    expect(outcome.reasons.join(' ')).not.toContain('dismissed by an inline')
  })

  it('does not count a dismissed medium finding toward review either', () => {
    const outcome = computeVerdict(verdictInput([
      dismissed('duplicate of the handler above, intentional', { severity: 'MEDIUM', category: 'TECH_DEBT', impactScore: 40 }),
    ]))

    expect(outcome.verdict).toBe('PASS')
  })
})

describe('the receipt records what was dismissed', () => {
  it('splits the delta into reported and dismissed, and reports dismissals repository-wide', () => {
    const reported = finding({ line: 9, title: 'Possible AWS access key committed in aws.ts' })
    const inDelta = dismissed('fixture credential for the local compose stack')
    const elsewhere = dismissed('vendored sample kept verbatim', { filePath: 'vendor/sample.ts', line: 2 })
    const rejected = finding({ filePath: 'src/api.ts', line: 12, suppression: { reason: '', markerLine: 11, applied: false } })

    const envelope = analyzerReceipt(
      analysis([reported, inDelta, elsewhere, rejected]),
      undefined,
      { introduced: [reported, inDelta, rejected], worsened: [], recurring: [elsewhere], resolved: [] },
    )

    expect(envelope.findings).toEqual([reported, rejected])
    expect(envelope.suppressed).toEqual([inDelta, elsewhere])
    expect(envelope.rejectedSuppressions).toEqual(['src/api.ts:11'])
  })

  it('omits both fields entirely when the repository dismissed nothing', () => {
    const envelope = analyzerReceipt(analysis([finding()]), undefined, {
      introduced: [finding()], worsened: [], recurring: [], resolved: [],
    })

    expect(envelope).not.toHaveProperty('suppressed')
    expect(envelope).not.toHaveProperty('rejectedSuppressions')
  })

  it('names the finding, its location, and the exact reason its author gave', () => {
    const receipt = receiptFixture('/tmp/repo')
    receipt.analyzers.suppressed = [dismissed('compose-only default | never deployed')]

    const markdown = renderMarkdown(receipt)

    expect(markdown).toContain('## Suppressed findings (1)')
    expect(markdown).toContain('This list covers the whole repository, not only the changed files.')
    // The pipe in the reason is escaped, so one comment cannot break the table.
    expect(markdown).toContain(
      '| HIGH | secrets | `src/db.ts:4` | Possible Database URL with credentials committed in db.ts | compose-only default \\| never deployed |',
    )
  })

  it('explains a marker that dismissed nothing rather than letting it fail in silence', () => {
    const receipt = receiptFixture('/tmp/repo')
    receipt.analyzers.rejectedSuppressions = ['src/api.ts:11']

    const markdown = renderMarkdown(receipt)

    expect(markdown).toContain('## Suppressed findings (0)')
    expect(markdown).toContain('Nothing was dismissed in this repository.')
    expect(markdown).toContain('1 `codetruss-ignore` marker(s) gave no reason and therefore dismissed nothing: `src/api.ts:11`')
    expect(markdown).toContain('Those findings are still reported above.')
  })

  it('renders a receipt that dismissed nothing exactly as before, so earlier signatures keep verifying', () => {
    const receipt = receiptFixture('/tmp/repo')
    receipt.analyzers.findings = [finding()]

    expect(renderMarkdown(receipt)).not.toContain('Suppressed findings')
    // A receipt whose signed JSON never knew about the field renders the same
    // bytes as one that knows about it and has nothing to report.
    const aware = structuredClone(receipt)
    aware.analyzers.suppressed = []
    aware.analyzers.rejectedSuppressions = []
    expect(renderMarkdown(aware)).toBe(renderMarkdown(receipt))
  })

  it('signs and verifies a receipt carrying dismissals', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-suppression-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = receiptFixture(root)
    receipt.analyzers.suppressed = [dismissed('reviewed 2026-08-06, dev-only container')]
    receipt.analyzers.rejectedSuppressions = ['src/api.ts:11']

    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    const verified = await verifyReceipt(dir, receipt.sessionId)
    const markdown = await readFile(paths.markdown, 'utf8')

    expect(verified.analyzers.suppressed).toHaveLength(1)
    expect(markdown).toContain('reviewed 2026-08-06, dev-only container')
  })
})

describe('sync keeps dismissals private-safe', () => {
  it('drops unrelated dismissals, redacts private paths from a reason, and keeps the related one', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-suppression-sync-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = receiptFixture(root, 'private patch')
    receipt.analyzers.suppressed = [
      dismissed('mirrors the constant in private/unrelated.ts', { metadata: { otherFile: 'private/unrelated.ts' } }),
      dismissed('whole-repo dismissal that must not sync', { filePath: 'private/unrelated.ts', line: 7 }),
    ]
    receipt.analyzers.rejectedSuppressions = ['src/db.ts:3', 'private/unrelated.ts:6']
    await writeReceipt(dir, receipt, 'private patch')

    const envelope = await createSyncEnvelope(receipt)
    const synced = JSON.parse(envelope.signedReceipt) as Receipt

    expect(synced.analyzers.suppressed).toHaveLength(1)
    expect(synced.analyzers.suppressed?.[0].filePath).toBe('src/db.ts')
    expect(synced.analyzers.suppressed?.[0].suppression?.reason).toBe('mirrors the constant in [redacted unrelated path]')
    expect(synced.analyzers.suppressed?.[0]).not.toHaveProperty('metadata')
    expect(synced.analyzers.rejectedSuppressions).toEqual(['src/db.ts:3'])
    expect(envelope.signedReceipt).not.toContain('private/unrelated.ts')
  })

  it('removes the fields entirely when nothing dismissed relates to a synced path', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-suppression-sync-empty-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = receiptFixture(root)
    receipt.analyzers.suppressed = [dismissed('unrelated', { filePath: 'private/unrelated.ts', line: 7 })]
    receipt.analyzers.rejectedSuppressions = ['private/unrelated.ts:6']
    await writeReceipt(dir, receipt, 'diff evidence')

    const synced = JSON.parse((await createSyncEnvelope(receipt)).signedReceipt) as Receipt

    expect(synced.analyzers).not.toHaveProperty('suppressed')
    expect(synced.analyzers).not.toHaveProperty('rejectedSuppressions')
  })
})
