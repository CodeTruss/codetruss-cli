import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { Writable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { runJournalCommand } from '../src/journal-command.js'
import { newSessionId, writeReceipt } from '../src/receipt.js'
import { loadSigningKey, verifyBytes } from '../src/signing.js'
import { DEFAULT_CONFIG } from '../src/config.js'
import { LOCAL_ANALYSIS_PROFILE, type CliConfig, type Receipt } from '../src/types.js'

/**
 * The field ask this exists for: receipts sat in .codetruss/ while the
 * contractor hand-built screenshots and worklogs, because nothing turned them
 * into an artifact a client could open. The journal is that artifact — and it
 * must stay honest: rendering is a view, evidence is the embedded signed
 * bytes, and nothing is ever silently dropped.
 */

const originalKey = process.env.CODETRUSS_SIGNING_KEY
afterEach(() => {
  if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY
  else process.env.CODETRUSS_SIGNING_KEY = originalKey
})

function fixture(root: string, overrides: Partial<Receipt> = {}, patch = 'diff evidence'): Receipt {
  const now = new Date(overrides.createdAt ?? '2026-08-12T15:00:00.123Z')
  return {
    receiptVersion: 1,
    sessionId: newSessionId(now),
    createdAt: now.toISOString(),
    finishedAt: now.toISOString(),
    durationMs: 0,
    mode: 'review',
    task: 'test receipt',
    repoRoot: root,
    startCommit: 'abc',
    endCommit: 'abc',
    git: { baselineTree: 'a'.repeat(40), finalTree: 'b'.repeat(40) },
    policy: { sha256: 'c'.repeat(64) },
    startDirty: false,
    startDirtyFiles: [],
    scope: { allow: ['src/**'], deny: [] },
    files: [{ path: 'src/auth.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 4, deletions: 1 }],
    diff: {
      sha256: createHash('sha256').update(patch).digest('hex'),
      bytes: Buffer.byteLength(patch),
      totalBytes: Buffer.byteLength(patch),
      truncated: false,
    },
    analyzers: { passes: [], findings: [], analysisProfile: LOCAL_ANALYSIS_PROFILE, index: { totalLoc: 0, languages: {}, primaryLanguage: null } },
    verifications: [{ command: 'tsc --noEmit', exitCode: 0, durationMs: 4200, output: 'compiled 88 files with zero errors', truncated: false }],
    coverageNotes: ['local'],
    verdict: 'PASS',
    reasons: ['no findings'],
    evidence: {},
    ...overrides,
  }
}

function sink(): { output: Writable; text: () => string } {
  let text = ''
  const output = new Writable({
    write(chunk, _encoding, callback) {
      text += String(chunk)
      callback()
    },
  })
  return { output, text: () => text }
}

async function journalRepo(): Promise<{ root: string; dir: string; config: CliConfig }> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-journal-'))
  process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing-private.pem')
  const key = await loadSigningKey(true)
  const config: CliConfig = {
    ...structuredClone(DEFAULT_CONFIG),
    signing: { publicKey: key.publicKey, publicKeys: [key.publicKey] },
  }
  return { root, dir: join(root, '.codetruss', 'receipts'), config }
}

describe('codetruss journal', () => {
  it('renders a self-contained journal whose embedded evidence round-trips', async () => {
    const { root, dir, config } = await journalRepo()
    await writeReceipt(dir, fixture(root, { createdAt: '2026-08-11T10:00:00.000Z', task: 'Wire the payment webhook' }, 'p1'), 'p1')
    await writeReceipt(dir, fixture(root, { createdAt: '2026-08-12T10:00:00.000Z', task: 'Scope order reads by organization' }, 'p2'), 'p2')

    const { output, text } = sink()
    const code = await runJournalCommand({ root, receiptDirectory: dir, config, includeOutput: false, output })
    expect(code).toBe(0)
    expect(text()).toContain('2 session(s)')

    const html = await readFile(join(root, '.codetruss', 'journal.html'), 'utf8')
    expect(html).toContain('Wire the payment webhook')
    expect(html).toContain('Scope order reads by organization')
    expect(html).toContain('tsc --noEmit')
    expect(html).toContain(basename(root))
    // The absolute path never appears; the repo is named by basename only.
    expect(html).not.toContain(`${root}/`)
    // Chronological: the older session renders first.
    expect(html.indexOf('Wire the payment webhook')).toBeLessThan(html.indexOf('Scope order reads by organization'))
    // Output is redacted by default; command, exit, and duration remain.
    expect(html).not.toContain('compiled 88 files')

    // Evidence round trip: the embedded base64 decodes to the exact signed
    // bytes on disk, and the advertised digest matches.
    const ids = (await import('../src/receipt.js')).receiptIds
    for (const id of await ids(dir)) {
      const signedJson = await readFile(join(dir, `${id}.json`), 'utf8')
      const encoded = Buffer.from(signedJson, 'utf8').toString('base64')
      expect(html).toContain(encoded)
      expect(html).toContain(createHash('sha256').update(signedJson, 'utf8').digest('hex'))
    }

    // The stranger's chain: extract the embedded evidence exactly as a
    // client's engineer would, write it to a fresh folder, and establish
    // integrity with the independent verifier.
    const { verifyReceiptIntegrity } = await import('../src/receipt.js')
    const extractDir = await mkdtemp(join(tmpdir(), 'codetruss-journal-extract-'))
    const evidence = [...html.matchAll(/download="([^"]+\.(?:json|md|sig))" href="data:[^;]+;base64,([^"]+)"/g)]
    expect(evidence.length).toBe(6)
    for (const [, name, encoded] of evidence) {
      await writeFile(join(extractDir, name), Buffer.from(encoded, 'base64'))
    }
    for (const id of await ids(dir)) {
      const result = await verifyReceiptIntegrity(join(extractDir, `${id}.json`))
      expect(result.intact, JSON.stringify(result.checks)).toBe(true)
    }

    // The journal manifest is signed by the local key and verifies.
    const manifestMatch = /<pre class="output">([^<]+)\n([A-Za-z0-9+/=]+)<\/pre>/.exec(html)
    expect(manifestMatch).not.toBeNull()
    const key = await loadSigningKey()
    const manifest = manifestMatch![1]
      .replaceAll('&amp;', '&').replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&#39;', "'")
    expect(verifyBytes(manifest, key.publicKey, manifestMatch![2])).toBe(true)
  })

  it('excludes a tampered receipt and says so instead of dropping it silently', async () => {
    const { root, dir, config } = await journalRepo()
    await writeReceipt(dir, fixture(root, { task: 'honest work' }, 'p1'), 'p1')
    const second = fixture(root, { createdAt: '2026-08-13T09:00:00.000Z', task: 'tampered work' }, 'p2')
    await writeReceipt(dir, second, 'p2')
    const tamperedPath = join(dir, `${second.sessionId}.json`)
    const raw = await readFile(tamperedPath, 'utf8')
    await writeFile(tamperedPath, raw.replace('tampered work', 'tampered work, honest'))

    const { output, text } = sink()
    await runJournalCommand({ root, receiptDirectory: dir, config, includeOutput: false, output })
    expect(text()).toContain('1 unverifiable receipt(s) excluded and disclosed')
    const html = await readFile(join(root, '.codetruss', 'journal.html'), 'utf8')
    expect(html).toContain('not in this journal')
    expect(html).toContain(second.sessionId)
  })

  it('excludes a receipt whose companion markdown is gone, naming it', async () => {
    const { root, dir, config } = await journalRepo()
    await writeReceipt(dir, fixture(root, { task: 'kept work' }, 'p1'), 'p1')
    const orphan = fixture(root, { createdAt: '2026-08-13T09:00:00.000Z', task: 'orphan work' }, 'p2')
    await writeReceipt(dir, orphan, 'p2')
    await rm(join(dir, `${orphan.sessionId}.md`))

    const { output, text } = sink()
    const code = await runJournalCommand({ root, receiptDirectory: dir, config, includeOutput: false, output })
    expect(code).toBe(0)
    expect(text()).toContain('1 session(s)')
    const html = await readFile(join(root, '.codetruss', 'journal.html'), 'utf8')
    expect(html).toContain('kept work')
    expect(html).toContain(orphan.sessionId)
    expect(html).toContain('not in this journal')
  })

  it('filters by --since and --until on session dates', async () => {
    const { root, dir, config } = await journalRepo()
    await writeReceipt(dir, fixture(root, { createdAt: '2026-08-01T10:00:00.000Z', task: 'old work' }, 'p1'), 'p1')
    await writeReceipt(dir, fixture(root, { createdAt: '2026-08-12T10:00:00.000Z', task: 'recent work' }, 'p2'), 'p2')

    const { output } = sink()
    await runJournalCommand({ root, receiptDirectory: dir, config, since: '2026-08-10', includeOutput: false, output })
    const html = await readFile(join(root, '.codetruss', 'journal.html'), 'utf8')
    expect(html).toContain('recent work')
    expect(html).not.toContain('old work')
  })

  it('escapes receipt text so a task cannot script the journal', async () => {
    const { root, dir, config } = await journalRepo()
    await writeReceipt(dir, fixture(root, { task: 'sneaky <script>alert(1)</script> task' }, 'p1'), 'p1')

    const { output } = sink()
    await runJournalCommand({ root, receiptDirectory: dir, config, includeOutput: false, output })
    const html = await readFile(join(root, '.codetruss', 'journal.html'), 'utf8')
    expect(html).not.toContain('<script>alert(1)')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('includes verification output only when asked', async () => {
    const { root, dir, config } = await journalRepo()
    await writeReceipt(dir, fixture(root, {}, 'p1'), 'p1')

    const { output } = sink()
    await runJournalCommand({ root, receiptDirectory: dir, config, includeOutput: true, output })
    const html = await readFile(join(root, '.codetruss', 'journal.html'), 'utf8')
    expect(html).toContain('compiled 88 files')
  })
})
