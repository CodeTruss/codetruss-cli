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
  it('finds the injection the hosted pass used to be needed for, and still withholds scores', async () => {
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
    // 13 registry analyzers plus the local security pass, which is deliberately
    // NOT in the registry so "13 deterministic analyzers" stays true.
    expect(analysis.passes).toHaveLength(14)
    expect(analysis.passes.at(-1)?.id).toBe('local-sast')

    const injection = analysis.findings.find((finding) => finding.metadata?.ruleId === 'sql-injection')
    expect(injection).toBeDefined()
    expect(injection?.severity).toBe('CRITICAL')
    expect(injection?.filePath).toBe('src/users.ts')
    expect(injection?.analyzerId).toBe('local-sast')

    // Scores remain withheld: the graph pass and the rest of the rule pack are
    // still absent, so any number would overstate what ran.
    expect(computeScores(analysis.index, analysis.findings).security).toBeLessThan(100)
    const evidence = analyzerReceipt(analysis)
    expect(evidence.analysisProfile).toEqual(LOCAL_ANALYSIS_PROFILE)
    expect(LOCAL_ANALYSIS_PROFILE.omittedPasses).toEqual(['graph'])
    expect(evidence).not.toHaveProperty('scores')
    expect(evidence).not.toHaveProperty('baselineScores')
  })

  it('discloses the rule classes the local security pass still does not check', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-local-sast-gap-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    // A repo large enough to draw coverage conclusions, entirely in a language
    // the local pass covers.
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
    expect(finding.title).toMatch(/reduced rule set/i)
    // "The pass ran" must never be allowed to read as "every class was checked".
    expect(finding.description).toMatch(/command injection/)
    expect(finding.description).toMatch(/path traversal/)
    expect(finding.description).toContain('means "not checked", not "clean"')
    expect(finding.metadata).toMatchObject({ sastPassRan: true })
    expect(finding.metadata?.sastUncheckedClasses).toContain('SSRF')
    // A disclosure, never a blocking accusation.
    expect(finding.severity).not.toBe('HIGH')
    expect(finding.severity).not.toBe('CRITICAL')
  })
})
