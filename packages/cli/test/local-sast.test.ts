import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { analyzeRepository, computeVerdict } from '../src/analysis.js'
import { LOCAL_SAST_PASS_ID, localSastInputs } from '../src/local-sast.js'
import type { AnalyzerFinding, RepoIndex } from '@codetruss/analyzer-engine'
import type { ChangedFile } from '../src/types.js'

const cleanup: string[] = []
afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function sastFinding(severity: AnalyzerFinding['severity'], ruleId: string): AnalyzerFinding {
  return {
    category: 'SECURITY_HYGIENE',
    severity,
    title: 'SQL injection',
    description: 'x',
    filePath: 'src/a.ts',
    line: 1,
    impactScore: 95,
    analyzerId: LOCAL_SAST_PASS_ID,
    metadata: { sast: true, ruleId },
  }
}

const changed: ChangedFile[] = [
  { path: 'src/a.ts', change: 'modified', classification: 'allowed', dependency: false, additions: 1, deletions: 0 },
]

describe('local security findings report without blocking the turn', () => {
  it('returns REVIEW_REQUIRED, not FAILED, for a critical local security finding', () => {
    const outcome = computeVerdict({
      verifications: [],
      files: changed,
      startDirty: false,
      findings: [sastFinding('CRITICAL', 'sql-injection')],
    })

    // A FAILED verdict at Stop halts the developer's agent. The local pass has
    // not earned that yet, so it must surface as review on its first release.
    expect(outcome.verdict).toBe('REVIEW_REQUIRED')
    expect(outcome.reasons).toContain('1 local security finding(s) affect changed files (sql-injection)')
    expect(outcome.reasons.join(' ')).not.toContain('high/critical security or dependency')
  })

  it('still fails on a high non-local security or dependency finding', () => {
    const outcome = computeVerdict({
      verifications: [],
      files: changed,
      startDirty: false,
      findings: [
        {
          category: 'SECURITY_HYGIENE',
          severity: 'HIGH',
          title: 'Committed credential',
          description: 'x',
          filePath: 'src/a.ts',
          impactScore: 90,
          analyzerId: 'secrets',
        },
      ],
    })
    expect(outcome.verdict).toBe('FAILED')
  })

  it('counts a local finding once, under its own reason', () => {
    const outcome = computeVerdict({
      verifications: [],
      files: changed,
      startDirty: false,
      findings: [sastFinding('MEDIUM', 'db-call-in-loop')],
    })
    expect(outcome.reasons.filter((reason) => reason.includes('finding(s)'))).toEqual([
      '1 local security finding(s) affect changed files (db-call-in-loop)',
    ])
  })
})

describe('local security pass file selection', () => {
  const index = (files: Array<{ path: string; kind: string }>): RepoIndex =>
    ({
      root: '/tmp',
      files: files.map((file) => ({ ...file, language: null, sizeBytes: 1, loc: 1, sha: null, content: 'const a = 1' })),
      languages: {},
      frameworks: [],
      packageManagers: [],
      databases: [],
      dependencies: new Set<string>(),
      totalLoc: 1,
      primaryLanguage: 'TypeScript',
      repoType: 'application',
      vendoredDirs: {},
    }) as unknown as RepoIndex

  it('analyzes production JS-family source only', () => {
    const inputs = localSastInputs(
      index([
        { path: 'src/a.ts', kind: 'source' },
        { path: 'src/b.tsx', kind: 'source' },
        { path: 'src/c.js', kind: 'source' },
        { path: 'src/d.test.ts', kind: 'test' },
        { path: 'vendor/e.js', kind: 'vendored' },
        { path: 'src/f.generated.ts', kind: 'generated' },
        { path: 'src/g.py', kind: 'source' },
        { path: 'src/h.go', kind: 'source' },
      ]),
    )
    expect(inputs.map((input) => input.filePath)).toEqual(['src/a.ts', 'src/b.tsx', 'src/c.js'])
  })

  it('skips declaration files, which hold no executable code to analyze', () => {
    const inputs = localSastInputs(
      index([
        { path: 'src/types.d.ts', kind: 'source' },
        { path: 'src/types.d.mts', kind: 'source' },
        { path: 'src/real.ts', kind: 'source' },
      ]),
    )
    expect(inputs.map((input) => input.filePath)).toEqual(['src/real.ts'])
  })
})

describe('the local pass is a pass, not a registry analyzer', () => {
  it('runs alongside the 13 registry analyzers without joining them', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-local-sast-pass-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'a.ts'), 'export const a = 1\n')

    const analysis = await analyzeRepository(root)
    const ids = analysis.passes.map((pass) => pass.id)
    expect(ids).toHaveLength(14)
    expect(ids.filter((id) => id === LOCAL_SAST_PASS_ID)).toHaveLength(1)
    expect(ids.at(-1)).toBe(LOCAL_SAST_PASS_ID)
    expect(analysis.passes.at(-1)?.result.complete).toBe(true)
  })

  it('reports a file it could not parse as lost coverage instead of staying silent', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-local-sast-degraded-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'broken.ts'), 'export function ( { !!! not parseable\n')

    const analysis = await analyzeRepository(root)
    const pass = analysis.passes.find((entry) => entry.id === LOCAL_SAST_PASS_ID)
    expect(pass?.result.complete).toBe(false)
    expect(pass?.result.truncated).toBe(true)
    expect(pass?.result.detail).toMatch(/could not be parsed locally/)
  })
})
