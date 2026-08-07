import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createSyncEnvelope, hookSessionId, newSessionId, renderLegacyMarkdown, renderMarkdown, renderPriorProfileMarkdown, verifyReceipt, writeReceipt } from '../src/receipt.js'
import { loadSigningKey, sha256, signBytes, verifyBytes } from '../src/signing.js'
import { LOCAL_ANALYSIS_PROFILE, type Receipt } from '../src/types.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY
afterEach(() => { if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY; else process.env.CODETRUSS_SIGNING_KEY = originalKey })

function fixture(root: string, patch = 'diff evidence'): Receipt {
  const now = new Date('2026-07-12T21:00:00.123Z')
  return {
    receiptVersion: 1, sessionId: newSessionId(now), createdAt: now.toISOString(), finishedAt: now.toISOString(), durationMs: 0,
    mode: 'review', task: 'test receipt', repoRoot: root, startCommit: 'abc', endCommit: 'abc',
    git: { baselineTree: 'a'.repeat(40), finalTree: 'b'.repeat(40) }, policy: { sha256: 'c'.repeat(64) }, startDirty: false, startDirtyFiles: [],
    scope: { allow: ['src/**'], deny: [] }, files: [], diff: {
      sha256: createHash('sha256').update(patch).digest('hex'),
      bytes: Buffer.byteLength(patch),
      totalBytes: Buffer.byteLength(patch),
      truncated: false,
    },
    analyzers: { passes: [], findings: [], analysisProfile: LOCAL_ANALYSIS_PROFILE, index: { totalLoc: 0, languages: {}, primaryLanguage: null } },
    verifications: [], coverageNotes: ['local'], verdict: 'PASS', reasons: ['no changes'], evidence: {},
  }
}

/** A receipt as CLI <= 0.2.34 signed it, when no security pass ran locally. */
function profileV1Fixture(root: string, patch = 'diff evidence'): Receipt {
  const receipt = fixture(root, patch)
  return {
    ...receipt,
    analyzers: {
      passes: receipt.analyzers.passes,
      findings: receipt.analyzers.findings,
      index: receipt.analyzers.index,
      analysisProfile: { id: 'local-registry-v1', omittedPasses: ['graph', 'sast'], scoreStatus: 'not-computed' },
    },
  }
}

function legacyFixture(root: string, patch = 'diff evidence'): Receipt {
  const receipt = fixture(root, patch)
  return {
    ...receipt,
    analyzers: {
      passes: receipt.analyzers.passes,
      findings: receipt.analyzers.findings,
      scores: { health: 100, debt: 100, architecture: 100, security: 100, docs: 100 },
      index: receipt.analyzers.index,
    },
  }
}

describe('signed receipts', () => {
  it('binds internal hook retries to one deterministic receipt path', () => {
    const now = new Date('2026-07-14T12:34:56.789Z')
    const attemptId = 'a'.repeat(64)
    expect(hookSessionId(now, attemptId)).toBe(`20260714T123456789Z-hook-${attemptId}`)
    expect(hookSessionId(now, attemptId)).toBe(hookSessionId(now, attemptId))
    expect(() => hookSessionId(now, 'A'.repeat(64))).toThrow(/attempt id is invalid/)
  })

  it('verifies JSON signature and Markdown/patch hashes and detects tampering', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-receipt-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    await expect(verifyReceipt(dir, receipt.sessionId)).resolves.toMatchObject({ verdict: 'PASS' })
    const markdown = await readFile(paths.markdown, 'utf8')
    expect(markdown).toContain('Policy SHA-256')
    expect(markdown).toContain('Profile: `local-registry-v2`')
    expect(markdown).not.toContain('Final scores:')
    await writeFile(paths.markdown, `${await readFile(paths.markdown, 'utf8')}tampered`)
    await expect(verifyReceipt(dir, receipt.sessionId)).rejects.toThrow('Markdown receipt does not match')
  })

  it('verifies old score-bearing Markdown but suppresses those legacy scores when reporting it now', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-legacy-receipt-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = legacyFixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    const oldMarkdown = renderLegacyMarkdown(receipt)
    receipt.evidence.markdownSha256 = sha256(oldMarkdown)
    const jsonText = `${JSON.stringify(receipt, null, 2)}\n`
    const key = await loadSigningKey()
    await writeFile(paths.json, jsonText)
    await writeFile(paths.markdown, oldMarkdown)
    await writeFile(paths.signature, `${signBytes(jsonText, key.privateKey)}\n`)

    const verified = await verifyReceipt(dir, receipt.sessionId)
    expect(oldMarkdown).toContain('Final scores: health 100')
    expect(renderMarkdown(verified)).toContain('Legacy local receipt')
    expect(renderMarkdown(verified)).toContain('**Hosted Health scores.** Not calculated, reported as **N/A**')
    expect(renderMarkdown(verified)).not.toContain('security 100')
  })

  it('names both what the local security pass checked and what it still did not', () => {
    const markdown = renderMarkdown(fixture('/tmp/repo'))
    const checked = markdown.slice(
      markdown.indexOf('### What the local security pass checked'),
      markdown.indexOf('### What did not run'),
    )
    const disclosure = markdown.slice(markdown.indexOf('### What did not run'))

    // Claiming coverage is only honest next to its own boundary.
    expect(checked).toContain('SQL injection')
    expect(checked).toContain('Mass assignment')
    expect(disclosure).toContain('**The rest of the security rule pack.**')
    expect(disclosure).toMatch(/Command injection.*path traversal.*SSRF/)
    expect(disclosure).toContain('means they were not analyzed, not that the code is clean')
    expect(disclosure).toContain('**Non-JavaScript languages.**')
    expect(disclosure).toContain('**Hosted symbol graph.**')
    expect(disclosure).toContain('**Optional LLM review.**')
    expect(disclosure).toContain('force-disabled under agent hooks')
    // The carve-out is stated where a reader will look for it.
    expect(markdown).toContain('do not fail the verdict on their own')
    // Never an accusation: the receipt reports what ran, not a verdict on the code.
    expect(disclosure).not.toMatch(/vulnerab|insecure code|unsafe/i)
    expect(markdown).toContain('It is not a statement that this change is secure.')
  })

  it('reproduces the v1 wording for a receipt signed before SAST ran locally', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-profile-v1-receipt-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = profileV1Fixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')

    const markdown = await readFile(paths.markdown, 'utf8')
    expect(markdown).toContain('Profile: `local-registry-v1`')
    // The claim that execution actually made, not the one the current CLI makes.
    expect(markdown).toContain('**Security static analysis (SAST).**')
    expect(markdown).not.toContain('### What the local security pass checked')
    await expect(verifyReceipt(dir, receipt.sessionId)).resolves.toMatchObject({ verdict: 'PASS' })
  })

  it('does not list the LLM review as omitted when a model actually reviewed the diff', () => {
    const receipt = fixture('/tmp/repo')
    receipt.llm = {
      provider: 'anthropic', transmittedBytes: 10,
      diffCoverage: { reviewedBytes: 13, totalBytes: 13, truncated: false },
      verdict: 'clean', summary: 'Nothing notable.', findings: [],
    }
    const markdown = renderMarkdown(receipt)
    expect(markdown).toContain('### What did not run')
    expect(markdown).not.toContain('**Optional LLM review.** No model read this diff')
    expect(markdown).toContain('## Optional LLM review')
  })

  it('still verifies a profile receipt whose Markdown carries the superseded wording', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-prior-profile-receipt-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = profileV1Fixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    const priorMarkdown = renderPriorProfileMarkdown(receipt)
    receipt.evidence.markdownSha256 = sha256(priorMarkdown)
    const jsonText = `${JSON.stringify(receipt, null, 2)}\n`
    const key = await loadSigningKey()
    await writeFile(paths.json, jsonText)
    await writeFile(paths.markdown, priorMarkdown)
    await writeFile(paths.signature, `${signBytes(jsonText, key.privateKey)}\n`)

    expect(priorMarkdown).toContain('Hosted Health scores: **N/A**.')
    expect(priorMarkdown).not.toContain('### What did not run')
    await expect(verifyReceipt(dir, receipt.sessionId)).resolves.toMatchObject({ verdict: 'PASS' })
  })

  it('still verifies a 0.2.30 receipt after the generated-exclusion disclosure is reworded', async () => {
    // Receipt Markdown is signed, and verifyReceipt only accepts renderings it
    // can reproduce. Analyzer wording is safe to change ONLY because it is
    // carried in the signed JSON rather than re-derived at render time — this
    // pins that. A receipt written by 0.2.30 with the superseded
    // "e.g. <first file>" disclosure must keep verifying byte-for-byte.
    const root = await mkdtemp(join(tmpdir(), 'codetruss-generated-disclosure-receipt-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixture(root)
    receipt.analyzers.findings = [{
      category: 'STRUCTURE',
      severity: 'LOW',
      analyzerId: 'structure',
      title: 'Generated code excluded from analysis (2 files, 448 KB)',
      description: 'CodeTruss detected 2 machine-generated or minified files (~22 LOC, 448 KB, e.g. `static/js/ace.js`) and excluded them from LOC totals, scores, and the architecture graph.',
      filePath: 'static/js/ace.js',
      impactScore: 20,
      effort: 'low',
    }]

    await writeReceipt(dir, receipt, 'diff evidence')

    await expect(verifyReceipt(dir, receipt.sessionId)).resolves.toMatchObject({ verdict: 'PASS' })
    const markdown = await readFile(join(dir, `${receipt.sessionId}.md`), 'utf8')
    expect(markdown).toContain('Generated code excluded from analysis (2 files, 448 KB)')
  })

  it('renders explicit optional LLM diff coverage', () => {
    const receipt = fixture('/tmp/repo')
    receipt.llm = {
      provider: 'openai', model: 'gpt-5.6-terra', transmittedBytes: 1_200,
      diffCoverage: { reviewedBytes: 200_000, totalBytes: 240_000, truncated: true },
      verdict: 'clean', summary: 'Reviewed the available prefix.', findings: [],
    }
    expect(renderMarkdown(receipt)).toContain('Reviewed 200000/240000 diff bytes (truncated; PASS prohibited).')
  })

  it('keeps receipt-v1 Markdown byte-compatible when signed JSON adds invocation provenance', () => {
    const current = fixture('/tmp/repo')
    current.invocation = { kind: 'agent_hook', provenance: 'hook_context', surface: 'codex', cliVersion: '0.2.14' }
    const preProvenance = structuredClone(current)
    delete preProvenance.invocation
    expect(renderMarkdown(current)).toBe(renderMarkdown(preProvenance))
  })

  it('discloses inferred scope as inferred, names what it was read from, and still verifies', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-inferred-scope-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixture(root)
    receipt.scope = {
      allow: ['lib/**'],
      deny: [],
      inferred: [{ root: 'src/auth', basis: 'working-set', evidence: ['src/auth/reset.ts', 'src/auth/tokens.ts'] }],
    }
    receipt.files = [
      { path: 'src/auth/reset.ts', change: 'added', classification: 'inferred', dependency: false, additions: 9, deletions: 0 },
      { path: 'src/auth/tokens.ts', change: 'modified', classification: 'inferred', dependency: false, additions: 2, deletions: 1 },
    ]
    await writeReceipt(dir, receipt, 'diff evidence')
    const markdown = renderMarkdown(receipt)

    // The changed-file row must never read as plainly approved scope.
    expect(markdown).toContain('| `src/auth/reset.ts` | added | allowed (inferred) |')
    expect(markdown).toContain('## Inferred scope (1)')
    expect(markdown).toContain('2 changed file(s) matched no approved allow root.')
    expect(markdown).toContain('| `src/auth` | working set for this turn | `src/auth/reset.ts`, `src/auth/tokens.ts` |')
    expect(markdown).toContain('applied them to this turn only')
    expect(markdown).toContain('were not written to `.codetruss.yml`')
    expect(markdown).toContain('Approved allow roots: `lib/**`.')
    expect(markdown).toContain('Denied paths, sensitive surfaces, and dependency manifests are never inferable.')
    await expect(verifyReceipt(dir, receipt.sessionId)).resolves.toMatchObject({ verdict: 'PASS' })
  })

  it('says the scope was inferred entirely when the repository approved no roots', () => {
    const receipt = fixture('/tmp/repo')
    receipt.scope = {
      allow: [],
      deny: [],
      inferred: [{ root: 'server/handlers', basis: 'task-reference', evidence: ['password reset'] }],
    }
    receipt.files = [{
      path: 'server/handlers/reset.ts', change: 'added', classification: 'inferred', dependency: false, additions: 9, deletions: 0,
    }]

    const markdown = renderMarkdown(receipt)

    expect(markdown).toContain('This repository has no approved allow roots, so its scope for this turn was inferred entirely.')
    expect(markdown).toContain('| `server/handlers` | named in the task | `password reset` |')
  })

  it('renders a receipt that inferred nothing exactly as before, so earlier signatures keep verifying', () => {
    const receipt = fixture('/tmp/repo')
    receipt.files = [
      { path: 'src/a.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 1, deletions: 0 },
      { path: 'infra/prod.tf', change: 'modified', classification: 'unexpected', sensitive: 'iac', dependency: false, additions: 1, deletions: 0 },
      { path: 'secrets/key.pem', change: 'added', classification: 'denied', sensitive: 'secrets', dependency: false, additions: 1, deletions: 0 },
    ]

    const markdown = renderMarkdown(receipt)

    expect(markdown).not.toContain('Inferred scope')
    expect(markdown).not.toContain('(inferred)')
    // Byte-for-byte the pre-inference rows: the Scope cell is the raw value.
    expect(markdown).toContain('| `src/a.ts` | modified | allowed | — | +1/−0 |')
    expect(markdown).toContain('| `infra/prod.tf` | modified | unexpected | iac | +1/−0 |')
    expect(markdown).toContain('| `secrets/key.pem` | added | denied | secrets | +1/−0 |')
    // An inference-free receipt renders identically whether or not the signed
    // JSON was written by a client that knew about the field at all.
    const preInference = structuredClone(receipt)
    preInference.scope = { allow: receipt.scope.allow, deny: receipt.scope.deny }
    expect(renderMarkdown(receipt)).toBe(renderMarkdown(preInference))
  })

  it('rejects a forged receipt signed by a substituted embedded key', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-receipt-forgery-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'trusted-signing.pem')
    const receipt = fixture(root)
    const paths = await writeReceipt(dir, receipt, 'diff evidence')
    const forged = JSON.parse(await readFile(paths.json, 'utf8')) as Receipt
    const attacker = generateKeyPairSync('ed25519')
    const attackerPublicKey = attacker.publicKey.export({ type: 'spki', format: 'pem' }).toString()
    forged.verdict = 'FAILED'
    forged.reasons = ['forged result']
    forged.evidence.publicKey = attackerPublicKey
    forged.evidence.keyFingerprint = createHash('sha256')
      .update(attacker.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex')
      .slice(0, 16)
    const forgedJson = `${JSON.stringify(forged, null, 2)}\n`
    await writeFile(paths.json, forgedJson)
    await writeFile(paths.signature, `${sign(null, Buffer.from(forgedJson), attacker.privateKey).toString('base64')}\n`)
    await expect(verifyReceipt(dir, receipt.sessionId)).rejects.toThrow('does not match trusted key')
  })

  it('signs a privacy-minimized sync copy', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-receipt-sync-'))
    const dir = join(root, 'receipts')
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const receipt = fixture(root, 'private patch')
    receipt.invocation = { kind: 'agent_hook', provenance: 'hook_context', surface: 'claude', cliVersion: '0.2.14' }
    receipt.startDirty = true
    receipt.startDirtyFiles = ['src/changed.ts', 'notes/private-plan.md']
    receipt.files = [{
      path: 'src/changed.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 2, deletions: 1,
    }]
    receipt.agent = { command: ['codex', 'secret prompt'], exitCode: 0, durationMs: 1 }
    receipt.verifications = [{ command: 'test', exitCode: 0, durationMs: 1, output: 'sensitive output', truncated: false }]
    const relevantFinding = {
      analyzerId: 'duplication', category: 'DUPLICATION' as const, severity: 'MEDIUM' as const,
      title: 'Duplicated logic: private/unrelated.ts and src/changed.ts',
      description: 'A block appears in both private/unrelated.ts and src/changed.ts.',
      suggestion: 'Extract private/unrelated.ts and src/changed.ts into one module.',
      filePath: 'src/changed.ts', line: 3, impactScore: 55, effort: 'medium' as const,
      metadata: { otherFile: 'private/unrelated.ts', otherLine: 7 },
    }
    const unrelatedFinding = {
      analyzerId: 'size', category: 'TECH_DEBT' as const, severity: 'LOW' as const,
      title: 'Private whole-repo finding', description: 'whole-repo body must not sync',
      filePath: 'private/unrelated.ts', line: 7, impactScore: 10,
    }
    receipt.analyzers.findings = [relevantFinding, unrelatedFinding]
    receipt.analyzers.passes = [{
      id: 'duplication',
      result: {
        findings: [relevantFinding, unrelatedFinding], complete: false, truncated: true,
        detail: 'failed while reading private/unrelated.ts', metrics: { privatePath: 'private/unrelated.ts' },
      },
      error: 'private analyzer error at private/unrelated.ts',
    }]
    await writeReceipt(dir, receipt, 'private patch')
    const envelope = await createSyncEnvelope(receipt)
    const synced = JSON.parse(envelope.signedReceipt) as Receipt
    expect(synced.repoRoot).toBe(basename(root))
    expect(synced.startDirtyFiles).toEqual(['src/changed.ts'])
    expect(synced.policy).toEqual({ sha256: 'c'.repeat(64) })
    expect(synced.invocation).toEqual({ kind: 'agent_hook', provenance: 'hook_context', surface: 'claude', cliVersion: '0.2.14' })
    expect(synced.agent?.command).toEqual(['codex'])
    expect(synced.verifications[0].command).toBe('[redacted for sync]')
    expect(synced.verifications[0].output).toBe('')
    expect(synced.analyzers.passes).toEqual([{
      id: 'duplication', result: { findings: [], complete: false, truncated: true },
    }])
    expect(synced.analyzers.findings).toEqual([{
      analyzerId: 'duplication', category: 'DUPLICATION', severity: 'MEDIUM',
      title: 'Duplicated logic: [redacted unrelated path] and src/changed.ts',
      description: 'A block appears in both [redacted unrelated path] and src/changed.ts.',
      suggestion: 'Extract [redacted unrelated path] and src/changed.ts into one module.',
      filePath: 'src/changed.ts', line: 3, impactScore: 55, effort: 'medium',
    }])
    expect(Object.keys(synced.evidence).sort()).toEqual(['keyFingerprint', 'patchSha256', 'publicKey'])
    expect(verifyBytes(envelope.signedReceipt, synced.evidence.publicKey!, envelope.signature)).toBe(true)
    expect(envelope.signedReceipt).not.toContain('secret prompt')
    expect(envelope.signedReceipt).not.toContain('sensitive output')
    expect(envelope.signedReceipt).not.toContain('"command": "test"')
    expect(envelope.signedReceipt).not.toContain('private patch')
    expect(envelope.signedReceipt).not.toContain('notes/private-plan.md')
    expect(envelope.signedReceipt).not.toContain('private/unrelated.ts')
    expect(envelope.signedReceipt).not.toContain('whole-repo body must not sync')
    expect(envelope.signedReceipt).not.toContain('private analyzer error')
  })
})
