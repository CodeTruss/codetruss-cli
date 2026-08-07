import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { computeScores } from '@codetruss/analyzer-engine'
import { afterEach, describe, expect, it } from 'vitest'
import { analyzeRepository, analyzerReceipt } from '../src/analysis.js'
import { LOCAL_ANALYSIS_PROFILE } from '../src/types.js'

const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

describe('honest local analysis profile', () => {
  it('does not emit a perfect security score when graph and SAST never ran', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-analysis-profile-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'users.ts'), [
      'export function findUser(',
      '  req: { query: { id: string } },',
      '  db: { query(sql: string): unknown },',
      ') {',
      '  return db.query("SELECT * FROM users WHERE id = " + req.query.id)',
      '}',
      '',
    ].join('\n'))

    const analysis = await analyzeRepository(root)
    expect(analysis.passes).toHaveLength(13)

    // This is the exact misleading value earlier CLI versions inferred from
    // registry-only findings even though the synthetic SQL injection was never
    // examined by the hosted SAST pass.
    expect(computeScores(analysis.index, analysis.findings).security).toBe(100)

    const evidence = analyzerReceipt(analysis)
    expect(evidence.analysisProfile).toEqual(LOCAL_ANALYSIS_PROFILE)
    expect(evidence).not.toHaveProperty('scores')
    expect(evidence).not.toHaveProperty('baselineScores')
    expect(JSON.stringify(evidence)).not.toContain('"security"')
  })

  it('discloses the absent SAST pass on the TypeScript repos where it used to stay silent', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-local-sast-gap-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    // A repo large enough to draw coverage conclusions, entirely in a language
    // the SAST engine covers — the exact shape that produced zero coverage
    // findings while the injection rules never ran.
    for (let unit = 0; unit < 8; unit += 1) {
      const body = Array.from({ length: 50 }, (_, line) => `  const value${line} = ${line} * ${unit + 1}`)
      await writeFile(
        join(root, 'src', `unit-${unit}.ts`),
        [`export function unit${unit}(): number {`, ...body, '  return value0', '}', ''].join('\n'),
      )
    }

    const analysis = await analyzeRepository(root)
    const coverage = analysis.passes.find((pass) => pass.id === 'coverage')
    expect(coverage?.result.findings).toHaveLength(1)
    const finding = coverage!.result.findings[0]
    expect(finding.category).toBe('SECURITY_HYGIENE')
    expect(finding.severity).toBe('INFO')
    expect(finding.title).toMatch(/did not run/i)
    expect(finding.description).toMatch(/SQL injection/)
    expect(finding.metadata).toMatchObject({ sastPassRan: false, sastLanguages: ['TypeScript'] })
    // A disclosure, never a blocking accusation: the local verdict must not
    // fail a change because a pass was absent.
    expect(finding.severity).not.toBe('HIGH')
    expect(finding.severity).not.toBe('CRITICAL')
  })
})
