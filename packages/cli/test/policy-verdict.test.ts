import { describe, expect, it } from 'vitest'
import { classifyPath, isDependencyFile, sensitiveCategory } from '../src/policy.js'
import { analysisCoverageNotes, analysisEvidenceIssues, computeVerdict, diffFindings } from '../src/analysis.js'
import type { AnalyzerFinding, AnalyzerPass, IndexCoverage } from '@codetruss/analyzer-engine'

describe('scope and sensitive policy', () => {
  it('is fail closed, gives deny precedence, and protects rename origins', () => {
    expect(classifyPath('src/a.ts', undefined, [], [])).toBe('unexpected')
    expect(classifyPath('src/a.ts', undefined, ['src/**'], ['src/a.ts'])).toBe('denied')
    expect(classifyPath('src/safe.ts', 'infra/prod.tf', ['src/**'], ['infra/**'])).toBe('denied')
  })

  it('flags sensitive surfaces and dependency lockfiles independently', () => {
    expect(sensitiveCategory('.github/workflows/ci.yml')).toBe('ci')
    expect(sensitiveCategory('infra/main.tf')).toBe('iac')
    expect(sensitiveCategory('prisma/migrations/1.sql')).toBe('migration')
    expect(sensitiveCategory('.env.production')).toBe('secrets')
    expect(isDependencyFile('packages/app/pnpm-lock.yaml')).toBe(true)
  })
})

describe('verdict rules', () => {
  const allowed = { path: 'src/a.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 1, deletions: 0 } as const
  it('returns PASS for in-scope verified changes', () => {
    expect(computeVerdict({ agentExitCode: 0, verifications: [{ command: 'test', exitCode: 0, durationMs: 1, output: '', truncated: false }], files: [allowed], startDirty: false, findings: [] }).verdict).toBe('PASS')
  })
  it('returns REVIEW_REQUIRED for scope drift and FAILED for command/check failure', () => {
    expect(computeVerdict({ agentExitCode: 0, verifications: [], files: [{ ...allowed, classification: 'unexpected' }], startDirty: false, findings: [] }).verdict).toBe('REVIEW_REQUIRED')
    expect(computeVerdict({ agentExitCode: 1, verifications: [], files: [allowed], startDirty: false, findings: [] }).verdict).toBe('FAILED')
    expect(computeVerdict({ agentExitCode: 0, verifications: [{ command: 'test', exitCode: 1, durationMs: 1, output: '', truncated: false }], files: [allowed], startDirty: false, findings: [] }).verdict).toBe('FAILED')
  })

  it('withholds PASS, without failing, when a required pass could not finish', () => {
    const outcome = computeVerdict({
      agentExitCode: 0,
      verifications: [],
      files: [allowed],
      startDirty: false,
      findings: [],
      evidenceIssues: [{ kind: 'partial', message: 'required analyzer secrets did not complete' }],
    })
    expect(outcome.verdict).toBe('REVIEW_REQUIRED')
    const passes = [
      { id: 'secrets', result: { findings: [], complete: false, detail: 'fixture failure' } },
      { id: 'vulnerabilities', result: { findings: [], complete: false, detail: 'offline policy' } },
    ] satisfies AnalyzerPass[]
    expect(analysisEvidenceIssues(passes, { discoveredFiles: 1, maxFiles: 10, truncated: false, textCandidates: 1, contentLoaded: 1, oversizedTextFiles: 0, unreadableTextFiles: 0, binaryTextFiles: 0 }))
      .toEqual([{ kind: 'partial', message: 'required analyzer secrets did not complete: fixture failure' }])
  })

  it('still fails closed when there is no evidence at all', () => {
    expect(analysisEvidenceIssues([], { discoveredFiles: 0, maxFiles: 10, truncated: false, textCandidates: 0, contentLoaded: 0, oversizedTextFiles: 0, unreadableTextFiles: 0, binaryTextFiles: 0 }))
      .toEqual([{ kind: 'missing', message: 'no required deterministic analyzer passes ran' }])
    expect(analysisEvidenceIssues([{ id: 'secrets', result: { findings: [], complete: true } }], undefined))
      .toEqual([{ kind: 'missing', message: 'repository index did not report coverage' }])
    const outcome = computeVerdict({
      agentExitCode: 0,
      verifications: [],
      files: [allowed],
      startDirty: false,
      findings: [],
      evidenceIssues: [{ kind: 'missing', message: 'no required deterministic analyzer passes ran' }],
    })
    expect(outcome.verdict).toBe('FAILED')
  })

  it('requires review when an incomplete baseline is fully repaired in the final tree', () => {
    const result = computeVerdict({
      agentExitCode: 0,
      verifications: [{ command: 'test', exitCode: 0, durationMs: 1, output: '', truncated: false }],
      files: [allowed],
      startDirty: false,
      findings: [],
      baselineEvidenceIssues: [{ kind: 'partial', message: '1 analyzable file could not be read' }],
    })
    expect(result).toEqual({
      verdict: 'REVIEW_REQUIRED',
      reasons: ['baseline evidence limitation resolved in the final tree: 1 analyzable file could not be read'],
    })
  })

  it('prohibits PASS when the requested LLM review covered only a diff prefix', () => {
    const result = computeVerdict({
      agentExitCode: 0,
      verifications: [{ command: 'test', exitCode: 0, durationMs: 1, output: '', truncated: false }],
      files: [allowed],
      startDirty: false,
      findings: [],
      llm: {
        provider: 'openai', model: 'gpt-5.6-terra', transmittedBytes: 1_000,
        diffCoverage: { reviewedBytes: 200_000, totalBytes: 250_000, truncated: true },
        verdict: 'clean', summary: 'No slop in the reviewed prefix.', findings: [],
      },
    })
    expect(result).toEqual({
      verdict: 'REVIEW_REQUIRED',
      reasons: ['local openai review covered 200000 of 250000 diff bytes'],
    })
  })
})

describe('analyzer finding deltas', () => {
  const finding = (overrides: Partial<AnalyzerFinding> = {}): AnalyzerFinding => ({
    category: 'SECURITY_HYGIENE', severity: 'HIGH', title: 'Hardcoded secret found',
    filePath: 'src/config.ts', line: 3, description: 'fixture', impactScore: 70, ...overrides,
  })

  it('does not gate a harmless edit on a pre-existing finding or shifted line', () => {
    const delta = diffFindings([finding()], [finding({ line: 40 })])
    expect(delta.introduced).toHaveLength(0)
    expect(delta.worsened).toHaveLength(0)
    expect(delta.recurring).toHaveLength(1)
  })

  it('detects introduced, worsened, resolved, global, and renamed-file findings', () => {
    const renamed = { path: 'src/new.ts', oldPath: 'src/config.ts', change: 'renamed', classification: 'allowed', dependency: false, additions: 0, deletions: 0 } as const
    const recurringAfterRename = finding({ filePath: 'src/new.ts' })
    const worsened = finding({ title: 'Complexity score 19', category: 'TECH_DEBT', severity: 'HIGH', impactScore: 80 })
    const priorWorse = finding({ title: 'Complexity score 12', category: 'TECH_DEBT', severity: 'MEDIUM', impactScore: 50 })
    const resolved = finding({ title: 'Old TODO 4', category: 'TECH_DEBT', severity: 'LOW', impactScore: 10 })
    const global = finding({ title: 'Coverage surface 1', category: 'TESTING', severity: 'MEDIUM', impactScore: 45, filePath: undefined })
    const delta = diffFindings([finding(), priorWorse, resolved], [recurringAfterRename, worsened, global], [renamed])
    expect(delta.recurring).toEqual([recurringAfterRename])
    expect(delta.worsened).toEqual([worsened])
    expect(delta.introduced).toEqual([global])
    expect(delta.resolved).toEqual([resolved])
  })

  it('keeps filename-bearing findings recurring across a rename', () => {
    const renamed = { path: 'src/new.ts', oldPath: 'src/old.ts', change: 'renamed', classification: 'allowed', dependency: false, additions: 0, deletions: 0 } as const
    const before = finding({ title: 'Possible AWS access key committed in old.ts', filePath: 'src/old.ts' })
    const after = finding({ title: 'Possible AWS access key committed in new.ts', filePath: 'src/new.ts' })
    expect(diffFindings([before], [after], [renamed])).toMatchObject({
      introduced: [], worsened: [], recurring: [after], resolved: [],
    })
  })
})

/**
 * A >1MB lockfile is ordinary in real repos. Failing a developer's FIRST
 * receipt over one file the agent never touched — with a reason naming no file
 * and no fix — reads as "this tool is broken". The hosted pipeline already
 * solved this (AUTHORITATIVE_COVERAGE_RATIO in src/lib/scans/analysis.ts); the
 * CLI applied zero tolerance to the identical IndexCoverage signal.
 */
describe('immaterial index coverage loss', () => {
  const coverage = (over: Partial<IndexCoverage>): IndexCoverage => ({
    discoveredFiles: 100,
    maxFiles: 5000,
    truncated: false,
    textCandidates: 100,
    contentLoaded: 100,
    oversizedTextFiles: 0,
    unreadableTextFiles: 0,
    binaryTextFiles: 0,
    ...over,
  })
  const passes = [{ id: 'secrets', result: { findings: [], complete: true } }] satisfies AnalyzerPass[]
  const inScope = { path: 'src/a.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 1, deletions: 0 } as const

  it('does not block on one oversized file in an otherwise fully read repo', () => {
    const c = coverage({ contentLoaded: 99, oversizedTextFiles: 1 })
    expect(analysisEvidenceIssues(passes, c)).toEqual([])
    const notes = analysisCoverageNotes(c)
    expect(notes).toHaveLength(1)
    // The reason must name the escape hatch, not just the symptom.
    expect(notes[0]).toContain('CODETRUSS_MAX_INDEX_FILE_BYTES')
  })

  it('still blocks when a real share of the repo went unread', () => {
    const c = coverage({ contentLoaded: 50, oversizedTextFiles: 50 })
    expect(analysisEvidenceIssues(passes, c).length).toBeGreaterThan(0)
    expect(analysisCoverageNotes(c)).toEqual([])
  })

  it('still blocks when the file walk hit its bound (no measurable denominator)', () => {
    const c = coverage({ truncated: true })
    expect(analysisEvidenceIssues(passes, c).length).toBeGreaterThan(0)
  })

  it('routes an immaterial coverage note to REVIEW_REQUIRED, not FAILED', () => {
    const result = computeVerdict({
      agentExitCode: 0,
      verifications: [],
      files: [inScope],
      startDirty: false,
      findings: [],
      advisoryEvidenceIssues: analysisCoverageNotes(coverage({ contentLoaded: 99, oversizedTextFiles: 1 })),
    })
    expect(result.verdict).toBe('REVIEW_REQUIRED')
  })
})
