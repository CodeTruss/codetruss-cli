import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { analyzerResult, analyzerWithheld, type AnalyzerFinding, type IndexedFile, type RepoIndex } from '@codetruss/analyzer-engine'
import { complexityAnalyzer } from '@codetruss/analyzer-engine/complexity'
import { analyzeRepository, analyzerReceipt, computeVerdict, diffFindings } from '../src/analysis.js'

/**
 * Analyzers cap their output. A cap bounds what a pass REPORTS about the whole
 * repository; it must never decide what a CHANGE is said to have done.
 *
 * Before the withheld set existed, it did exactly that. Resolve two complexity
 * findings and two cap slots free up; two previously capped findings — in files
 * the author never opened — enter the reported list for the first time, and the
 * delta calls them introduced. A signed receipt then asserted that a change
 * broke code it never touched, and drove REVIEW_REQUIRED off that claim.
 *
 * These are the two directions of that bug, plus the wiring that keeps the
 * withheld findings out of the receipt they exist to protect.
 */

const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function file(path: string, content: string): IndexedFile {
  return {
    path,
    language: 'TypeScript',
    kind: 'source',
    sizeBytes: content.length,
    loc: content.split('\n').filter((line) => line.trim()).length,
    sha: null,
    content,
  }
}

/**
 * File order in the index is the order the complexity analyzer emits findings
 * in, and therefore which of them the cap keeps. The fixtures build the index
 * directly so the cap boundary is exact rather than left to directory order.
 */
function index(files: IndexedFile[]): RepoIndex {
  return {
    root: '/tmp/capped-delta',
    files,
    languages: { TypeScript: 1000 },
    frameworks: [],
    packageManagers: ['pnpm'],
    databases: [],
    dependencies: new Set(),
    totalLoc: 1000,
    vendoredDirs: {},
    repoType: 'application',
    primaryLanguage: 'TypeScript',
  }
}

/** One deep-nesting finding: control-flow depth 8 against a limit of 5. */
function nested(name: string, marker = ''): string {
  const opens = Array.from({ length: 7 }, (_, level) => `${'  '.repeat(level + 1)}if (n > ${level}) {`)
  if (marker) opens.splice(6, 0, `${'  '.repeat(7)}// codetruss-ignore: ${marker}`)
  const closes = Array.from({ length: 7 }, (_, level) => `${'  '.repeat(7 - level)}}`)
  return [`export function ${name}(n: number) {`, ...opens, '        return n', ...closes, '  return 0', '}', ''].join('\n')
}

/** Same signature, no nesting: the finding this fixture had is gone. */
function flat(name: string): string {
  return `export function ${name}(n: number) {\n  return n > 0 ? n : 0\n}\n`
}

async function complexity(files: IndexedFile[]): Promise<{ reported: AnalyzerFinding[]; withheld: AnalyzerFinding[] }> {
  const output = await complexityAnalyzer.run(index(files))
  return { reported: analyzerResult(output).findings, withheld: analyzerWithheld(output) }
}

const paths = (findings: AnalyzerFinding[]) => findings.map((finding) => finding.filePath).sort()

describe('an output cap does not decide what a change introduced', () => {
  /**
   * Baseline sits ON the cap: 24 matches, 20 reported, 4 withheld. The two
   * files the change touches are first, so resolving them frees exactly two cap
   * slots for findings that were already there.
   */
  const touched = ['src/a-touched-one.ts', 'src/a-touched-two.ts']
  const untouched = Array.from({ length: 22 }, (_, i) => `src/m-${String(i).padStart(2, '0')}.ts`)

  const baselineFiles = [
    ...touched.map((path, i) => file(path, nested(`touched${i}`))),
    ...untouched.map((path, i) => file(path, nested(`mod${i}`))),
  ]
  const finalFiles = [
    ...touched.map((path, i) => file(path, flat(`touched${i}`))),
    ...untouched.map((path, i) => file(path, nested(`mod${i}`))),
  ]
  const changed = touched.map((path) => ({
    path, change: 'modified', classification: 'allowed', dependency: false, additions: 1, deletions: 12,
  } as const))

  it('reproduces the cap surfacing: two fixes free two slots for findings already present', async () => {
    const before = await complexity(baselineFiles)
    const after = await complexity(finalFiles)

    // Baseline is at the cap with four matches held back.
    expect(before.reported).toHaveLength(20)
    expect(before.withheld).toHaveLength(4)
    // The change removed two findings, so the final tree has two fewer matches
    // — still over the cap, still reporting twenty.
    expect(after.reported).toHaveLength(20)
    expect(after.withheld).toHaveLength(2)

    // Two findings that were withheld in the baseline are now reported, and
    // neither of their files was touched. This is the exact input that used to
    // produce a false "introduced".
    const surfaced = paths(after.reported).filter((path) => !paths(before.reported).includes(path!))
    expect(surfaced).toHaveLength(2)
    expect(surfaced.every((path) => !touched.includes(path!))).toBe(true)
    expect(paths(before.withheld)).toEqual(expect.arrayContaining(surfaced))

    // Comparing reported lists alone — the behaviour before the withheld set
    // existed — blames the change for both of them.
    const reportedOnly = diffFindings(before.reported, after.reported, changed)
    expect(paths(reportedOnly.introduced)).toEqual(surfaced)
  })

  it('reports nothing as introduced when every final finding was already in the baseline', async () => {
    const before = await complexity(baselineFiles)
    const after = await complexity(finalFiles)

    const delta = diffFindings(before.reported, after.reported, changed, {
      baseline: before.withheld,
      final: after.withheld,
    })

    expect(delta.introduced).toEqual([])
    expect(delta.worsened).toEqual([])
    // The two fixed files are the only thing this change did.
    expect(paths(delta.resolved)).toEqual(touched)
    // Every remaining match recurs — all 22, not the 20 the cap happened to
    // show. The delta counts on the receipt describe the repository, not the
    // width of a display window.
    expect(delta.recurring).toHaveLength(22)
  })

  it('keeps a REVIEW_REQUIRED verdict from resting on findings the change did not introduce', async () => {
    const before = await complexity(baselineFiles)
    const after = await complexity(finalFiles)
    const allowed = changed.map((entry) => ({ ...entry, sensitive: undefined }))

    const verdictFor = (delta: { introduced: AnalyzerFinding[]; worsened: AnalyzerFinding[] }) => computeVerdict({
      agentExitCode: 0,
      verifications: [{ command: 'test', exitCode: 0, durationMs: 1, output: '', truncated: false }],
      files: allowed,
      startDirty: false,
      findings: [...delta.introduced, ...delta.worsened],
    })

    // The surfaced findings are MEDIUM, so the old comparison did not merely
    // mislabel them — it changed the verdict of a change that fixed two files.
    expect(verdictFor(diffFindings(before.reported, after.reported, changed)).verdict).toBe('REVIEW_REQUIRED')
    expect(verdictFor(diffFindings(before.reported, after.reported, changed, {
      baseline: before.withheld,
      final: after.withheld,
    })).verdict).toBe('PASS')
  })

  it('does not report a finding as resolved when new findings pushed it below the cap', async () => {
    // The mirror image: a change that ADDS findings takes cap slots away, and
    // untouched findings drop out of the reported list without being fixed.
    const added = Array.from({ length: 4 }, (_, i) => file(`src/a-new-${i}.ts`, nested(`added${i}`)))
    const before = await complexity(untouched.map((path, i) => file(path, nested(`mod${i}`))))
    const after = await complexity([...added, ...untouched.map((path, i) => file(path, nested(`mod${i}`)))])
    const additions = added.map((entry) => ({
      path: entry.path, change: 'added', classification: 'allowed', dependency: false, additions: 18, deletions: 0,
    } as const))

    expect(before.reported).toHaveLength(20)
    expect(after.reported).toHaveLength(20)

    // Reported lists alone: four untouched findings read as fixed.
    expect(diffFindings(before.reported, after.reported, additions).resolved).toHaveLength(4)

    const delta = diffFindings(before.reported, after.reported, additions, {
      baseline: before.withheld,
      final: after.withheld,
    })
    expect(delta.resolved).toEqual([])
    expect(paths(delta.introduced)).toEqual(paths(added.map((entry) => ({ filePath: entry.path } as AnalyzerFinding))))
  })
})

describe('withheld findings are evidence for the comparison, never receipt content', () => {
  async function cappedRepo(marker = ''): Promise<Awaited<ReturnType<typeof analyzeRepository>>> {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-capped-delta-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    await Promise.all(Array.from({ length: 26 }, (_, i) =>
      writeFile(join(root, 'src', `deep-${String(i).padStart(2, '0')}.ts`), nested(`deep${i}`, marker))))
    return analyzeRepository(root)
  }

  it('carries the over-cap findings out of analyzeRepository without reporting them', async () => {
    const analysis = await cappedRepo()

    const complexityPass = analysis.passes.find((pass) => pass.id === 'complexity')
    expect(complexityPass?.result.findings).toHaveLength(20)
    expect(complexityPass?.result.complete).toBe(true)

    const withheldComplexity = analysis.withheld.filter((finding) => finding.analyzerId === 'complexity')
    expect(withheldComplexity).toHaveLength(6)

    // The receipt still shows exactly what the cap allows: the withheld
    // findings answer "did this exist before?" and nothing else.
    const receipt = analyzerReceipt(analysis, undefined, {
      introduced: [], worsened: [], recurring: analysis.findings, resolved: [],
    })
    expect(receipt).not.toHaveProperty('withheld')
    expect(receipt.passes.flatMap((pass) => pass.result.findings)).not.toEqual(
      expect.arrayContaining(withheldComplexity),
    )
  })

  it('reads inline dismissals over withheld findings too, so one reaching the delta stays dismissed', async () => {
    // A finding can reach the receipt from beyond the cap — it only has to be
    // absent from the baseline. A `codetruss-ignore` beside it has to hold when
    // it does, or the cap would decide whose markers are honoured.
    const analysis = await cappedRepo('deliberate fixture nesting')

    const withheldComplexity = analysis.withheld.filter((finding) => finding.analyzerId === 'complexity')
    expect(withheldComplexity).toHaveLength(6)
    expect(withheldComplexity.every((finding) => finding.suppression?.applied)).toBe(true)
    expect(withheldComplexity[0].suppression?.reason).toBe('deliberate fixture nesting')
  })
})
