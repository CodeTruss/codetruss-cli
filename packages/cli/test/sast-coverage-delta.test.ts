import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import type { AnalyzerFinding } from '@codetruss/analyzer-engine'
import { analyzeRepository, diffFindings } from '../src/analysis.js'
import { LOCAL_SAST_PASS_ID, sastCoverageGap, type SastCoverageGap } from '../src/local-sast.js'
import type { ChangedFile } from '../src/types.js'

/**
 * A wall-clock ceiling in the security pass must not make the delta lie.
 *
 * The output-cap version of this bug is pinned in capped-finding-delta.test.ts,
 * and the fix there — compare against what the pass withheld — cannot work here.
 * A capped finding was found and dropped, so it can be handed over as evidence.
 * A file the clock cut was never analyzed: nothing was computed, and the tree's
 * state there is unknown rather than clean.
 *
 * The node budget never had this problem because it is a function of the file's
 * own bytes: it hides the same findings in both trees, and they cancel out. A
 * clock does not fire identically twice. Cut a file in the baseline and not in
 * the final and its long-standing findings show up on one side only — and the
 * receipt says a change broke a file its author never opened.
 */

const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function sast(filePath: string, title = 'Database query inside a loop (N+1)'): AnalyzerFinding {
  return {
    category: 'SECURITY_HYGIENE',
    severity: 'MEDIUM',
    title,
    description: 'x',
    filePath,
    line: 1,
    impactScore: 40,
    analyzerId: LOCAL_SAST_PASS_ID,
    metadata: { sast: true, ruleId: 'db-call-in-loop' },
  }
}

/** A deterministic analyzer's finding: unaffected by where SAST ran out of time. */
function analyzerFinding(filePath: string): AnalyzerFinding {
  return {
    category: 'COMPLEXITY',
    severity: 'MEDIUM',
    title: 'Deeply nested control flow',
    description: 'x',
    filePath,
    line: 1,
    impactScore: 30,
    analyzerId: 'complexity',
  }
}

const clean: SastCoverageGap = { paths: [], incomplete: false }
const cut = (...paths: string[]): SastCoverageGap => ({ paths, incomplete: false })
const titles = (findings: AnalyzerFinding[]) => findings.map((finding) => finding.title).sort()

describe('a clock-cut file is not evidence, in either direction', () => {
  it('does not call a finding introduced when the baseline could not see its file', () => {
    // Same file, same bytes, both trees. The baseline's clock fired; the final's
    // did not. Nothing about this file changed.
    const delta = diffFindings([], [sast('src/untouched.ts')], [], {}, [cut('src/untouched.ts'), clean])

    expect(delta.introduced).toEqual([])
    // And it is not smuggled into another bucket either — the delta makes no
    // claim at all about a file it could not read.
    expect(delta.worsened).toEqual([])
    expect(delta.recurring).toEqual([])
    expect(delta.resolved).toEqual([])
  })

  it('does not call a finding resolved when the final could not see its file', () => {
    const delta = diffFindings([sast('src/untouched.ts')], [], [], {}, [clean, cut('src/untouched.ts')])

    expect(delta.resolved).toEqual([])
    expect(delta.introduced).toEqual([])
  })

  it('still attributes findings in files both trees finished analyzing', () => {
    const delta = diffFindings(
      [],
      [sast('src/changed.ts'), sast('src/slow.ts')],
      [],
      {},
      [cut('src/slow.ts'), clean],
    )

    // The gap is per-file, not per-run: one pathological file must not neutralize
    // the security signal for the file the author actually broke.
    expect(titles(delta.introduced)).toEqual(['Database query inside a loop (N+1)'])
    expect(delta.introduced[0]?.filePath).toBe('src/changed.ts')
  })

  it('leaves deterministic analyzers alone — a SAST ceiling is not their gap', () => {
    const delta = diffFindings([], [analyzerFinding('src/slow.ts')], [], {}, [cut('src/slow.ts'), clean])

    expect(titles(delta.introduced)).toEqual(['Deeply nested control flow'])
  })

  it('matches a renamed file by either spelling', () => {
    // The baseline names the gap by the old path; the finding arrives under the new one.
    const files: ChangedFile[] = [
      { path: 'src/new.ts', oldPath: 'src/old.ts', change: 'renamed', classification: 'allowed', dependency: false, additions: 0, deletions: 0 },
    ]
    const delta = diffFindings([], [sast('src/new.ts')], files, {}, [cut('src/old.ts'), clean])

    expect(delta.introduced).toEqual([])
  })
})

describe('when the run cut more files than it could name', () => {
  it('stops attributing SAST findings at all rather than trusting a partial list', () => {
    // The whole-pass ceiling skips every remaining file and names only the first
    // 50. Filtering by that list would still blame the change for the rest.
    const partial: SastCoverageGap = { paths: ['src/a.ts'], incomplete: true }
    const delta = diffFindings([], [sast('src/a.ts'), sast('src/z.ts')], [], {}, [partial, clean])

    expect(delta.introduced).toEqual([])
  })

  it('still leaves deterministic analyzers attributable', () => {
    const partial: SastCoverageGap = { paths: [], incomplete: true }
    const delta = diffFindings([], [analyzerFinding('src/z.ts'), sast('src/z.ts')], [], {}, [partial, clean])

    expect(titles(delta.introduced)).toEqual(['Deeply nested control flow'])
  })
})

describe('reading the gap out of scan diagnostics', () => {
  const diagnostics = {
    inputFiles: 3,
    filesScanned: 2,
    filesSkipped: 1,
    degradedLanguages: [],
    truncatedFiles: 0,
    findingsTruncated: false,
  }

  it('is empty and complete when no ceiling fired', () => {
    expect(sastCoverageGap(diagnostics)).toEqual({ paths: [], incomplete: false })
  })

  it('carries both ceilings’ paths', () => {
    expect(
      sastCoverageGap({
        ...diagnostics,
        timeCappedFiles: 1,
        timeCappedPaths: ['slow.py'],
        timeSkippedFiles: 1,
        timeSkippedPaths: ['never.py'],
      }),
    ).toEqual({ paths: ['slow.py', 'never.py'], incomplete: false })
  })

  it('is incomplete when the counts exceed the names', () => {
    // The whole-pass ceiling skips thousands and names 50. The names are not the set.
    expect(
      sastCoverageGap({ ...diagnostics, timeSkippedFiles: 4, timeSkippedPaths: ['a.py', 'b.py'] }).incomplete,
    ).toBe(true)
    expect(
      sastCoverageGap({ ...diagnostics, timeCappedFiles: 3, timeCappedPaths: ['a.py'] }).incomplete,
    ).toBe(true)
  })
})

describe('the gap a real run reports', () => {
  it('is empty and complete when every file finished', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-sast-gap-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'a.ts'), 'export const a = 1\n')

    const analysis = await analyzeRepository(root)
    expect(analysis.sastCoverageGap).toEqual({ paths: [], incomplete: false })
  })
})
