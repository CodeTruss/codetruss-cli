import { createHash } from 'node:crypto'
import { runAnalyzers, type AnalyzerFinding, type AnalyzerPass, type IndexCoverage } from '@codetruss/analyzer-engine'
import { indexRepository } from './indexer.js'
import { LOCAL_ANALYSIS_PROFILE, type ChangedFile, type Receipt, type VerificationResult, type Verdict, type LlmReview } from './types.js'

export async function analyzeRepository(root: string) {
  const index = await indexRepository(root)
  const priorOffline = process.env.CODETRUSS_OFFLINE
  process.env.CODETRUSS_OFFLINE = '1'
  try {
    // LOCAL_ANALYSIS_PROFILE omits the SAST pass. Declaring it here is what
    // makes the coverage analyzer disclose the gap instead of inheriting the
    // hosted premise that TypeScript/JavaScript/Python were security-reviewed.
    const result = await runAnalyzers(index, { sast: false })
    return { ...result, index }
  } finally {
    if (priorOffline === undefined) delete process.env.CODETRUSS_OFFLINE
    else process.env.CODETRUSS_OFFLINE = priorOffline
  }
}

const severityRank = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const

function normalizedFindingPath(path: string | undefined, files: ChangedFile[]): string {
  if (!path) return ''
  const renamed = files.find((file) => file.change === 'renamed' && file.oldPath && (path === file.path || path.startsWith(`${file.path}/`)))
  if (!renamed?.oldPath) return path
  return `${renamed.oldPath}${path.slice(renamed.path.length)}`
}

function normalizedFindingTitle(finding: AnalyzerFinding, files: ChangedFile[]): string {
  let title = finding.title
  for (const file of files) {
    if (file.change !== 'renamed' || !file.oldPath) continue
    title = title.replaceAll(file.path, file.oldPath)
    const currentName = file.path.split('/').at(-1)
    const priorName = file.oldPath.split('/').at(-1)
    if (currentName && priorName) title = title.replaceAll(currentName, priorName)
  }
  return title.replace(/\d+/g, '#').toLowerCase().trim()
}

/** Match the hosted finding lifecycle contract while ignoring volatile line numbers and counts. */
export function findingFingerprint(finding: AnalyzerFinding, files: ChangedFile[] = []): string {
  return createHash('sha1')
    .update([finding.category, normalizedFindingTitle(finding, files), normalizedFindingPath(finding.filePath, files)].join('|'))
    .digest('hex')
}

export interface FindingDelta {
  introduced: AnalyzerFinding[]
  worsened: AnalyzerFinding[]
  recurring: AnalyzerFinding[]
  resolved: AnalyzerFinding[]
}

function isWorse(current: AnalyzerFinding, baseline: AnalyzerFinding): boolean {
  return severityRank[current.severity] > severityRank[baseline.severity] || current.impactScore > baseline.impactScore
}

/** Compare exact baseline and final analyzer results; only introduced/worsened findings gate the verdict. */
export function diffFindings(
  baseline: AnalyzerFinding[],
  final: AnalyzerFinding[],
  files: ChangedFile[] = [],
): FindingDelta {
  const before = new Map(baseline.map((finding) => [findingFingerprint(finding), finding]))
  const after = new Map(final.map((finding) => [findingFingerprint(finding, files), finding]))
  const introduced: AnalyzerFinding[] = []
  const worsened: AnalyzerFinding[] = []
  const recurring: AnalyzerFinding[] = []
  const resolved: AnalyzerFinding[] = []

  for (const [fingerprint, finding] of after) {
    const prior = before.get(fingerprint)
    if (!prior) introduced.push(finding)
    else if (isWorse(finding, prior)) worsened.push(finding)
    else recurring.push(finding)
  }
  for (const [fingerprint, finding] of before) {
    if (!after.has(fingerprint)) resolved.push(finding)
  }
  return { introduced, worsened, recurring, resolved }
}

/**
 * A partially-read index still counts as authoritative when it measurably
 * covered at least this fraction of its analyzable input. Mirrors
 * AUTHORITATIVE_COVERAGE_RATIO in the hosted pipeline (src/lib/scans/analysis.ts):
 * an immaterial cap (one oversized lockfile) must not void the receipt, while a
 * real coverage loss still withholds one.
 */
export const AUTHORITATIVE_COVERAGE_RATIO = 0.95

/**
 * Text files loaded over analyzable text candidates. Binary files masquerading
 * as text are not analyzable and never count against coverage. The file-walk
 * cap has no measurable denominator — unwalked files are unknown — so a
 * truncated walk claims no ratio.
 */
export function indexCoverageRatio(coverage: IndexCoverage | undefined): number | undefined {
  if (!coverage || coverage.truncated) return undefined
  const analyzable = coverage.textCandidates - coverage.binaryTextFiles
  if (analyzable <= 0) return 1
  return coverage.contentLoaded / analyzable
}

function coverageIsAuthoritative(coverage: IndexCoverage | undefined): boolean {
  const ratio = indexCoverageRatio(coverage)
  return ratio !== undefined && ratio >= AUTHORITATIVE_COVERAGE_RATIO
}

/** Content-loading limitations, worded so the reader learns the fix, not just the symptom. */
function coverageLimitations(coverage: IndexCoverage): string[] {
  const limitations: string[] = []
  if (coverage.oversizedTextFiles > 0) {
    limitations.push(
      `${coverage.oversizedTextFiles} oversized analyzable file(s) were not read — raise CODETRUSS_MAX_INDEX_FILE_BYTES to include them`,
    )
  }
  if (coverage.unreadableTextFiles > 0) limitations.push(`${coverage.unreadableTextFiles} analyzable file(s) could not be read`)
  if (coverage.binaryTextFiles > 0) limitations.push(`${coverage.binaryTextFiles} apparent text file(s) contained binary data`)
  return limitations
}

/**
 * Offline vulnerability lookup is advisory; every deterministic pass is
 * required. Index limitations are required too, EXCEPT when the index still
 * measurably covered >= AUTHORITATIVE_COVERAGE_RATIO of its analyzable input —
 * those are returned by analysisCoverageNotes() as review-level instead, so a
 * single large lockfile cannot fail an otherwise clean receipt.
 */
export function analysisEvidenceIssues(
  passes: AnalyzerPass[],
  coverage: IndexCoverage | undefined,
): string[] {
  const issues: string[] = []
  const requiredPasses = passes.filter((pass) => pass.id !== 'vulnerabilities')
  if (requiredPasses.length === 0) issues.push('no required deterministic analyzer passes ran')
  for (const pass of requiredPasses) {
    if (pass.error || !pass.result.complete || pass.result.truncated) {
      issues.push(`required analyzer ${pass.id} did not complete${pass.result.detail ? `: ${pass.result.detail}` : ''}`)
    }
  }
  if (!coverage) issues.push('repository index did not report coverage')
  else {
    if (coverage.truncated) issues.push(`repository index reached its ${coverage.maxFiles}-file bound`)
    if (!coverageIsAuthoritative(coverage)) issues.push(...coverageLimitations(coverage))
  }
  return issues
}

/**
 * Index limitations small enough to leave the evidence authoritative. Surfaced
 * on the receipt as review-level context rather than suppressed — the reader
 * still learns exactly what was not read.
 */
export function analysisCoverageNotes(coverage: IndexCoverage | undefined): string[] {
  if (!coverage || !coverageIsAuthoritative(coverage)) return []
  return coverageLimitations(coverage)
}

export function changedFindings(findings: AnalyzerFinding[], files: ChangedFile[]): AnalyzerFinding[] {
  const changed = new Set(files.flatMap((file) => [file.path, file.oldPath].filter(Boolean) as string[]))
  return findings.filter((finding) => {
    const filePath = finding.filePath
    return Boolean(filePath && [...changed].some((path) => filePath === path || filePath.startsWith(`${path}/`) || path.startsWith(`${filePath}/`)))
  })
}

export function computeVerdict(input: {
  agentExitCode?: number
  verifications: VerificationResult[]
  files: ChangedFile[]
  startDirty: boolean
  findings: AnalyzerFinding[]
  llm?: LlmReview
  evidenceIssues?: string[]
  baselineEvidenceIssues?: string[]
  advisoryEvidenceIssues?: string[]
}): { verdict: Verdict; reasons: string[] } {
  const failed: string[] = []
  const review: string[] = []
  const notes: string[] = []
  if (input.agentExitCode !== undefined && input.agentExitCode !== 0) failed.push(`agent command exited with code ${input.agentExitCode}`)
  for (const issue of input.evidenceIssues ?? []) failed.push(`evidence incomplete: ${issue}`)
  for (const issue of input.baselineEvidenceIssues ?? []) review.push(`baseline evidence limitation resolved in the final tree: ${issue}`)
  for (const issue of input.advisoryEvidenceIssues ?? []) review.push(`index coverage was partial but authoritative: ${issue}`)
  for (const verification of input.verifications.filter((item) => item.exitCode !== 0)) failed.push(`verification command failed: ${verification.command}`)
  const blocking = input.findings.filter((finding) => severityRank[finding.severity] >= severityRank.HIGH && (finding.category === 'SECURITY_HYGIENE' || finding.category === 'DEPENDENCY'))
  if (blocking.length) failed.push(`${blocking.length} high/critical security or dependency finding(s) affect changed files`)
  const denied = input.files.filter((file) => file.classification === 'denied')
  const unexpected = input.files.filter((file) => file.classification === 'unexpected')
  const sensitive = input.files.filter((file) => file.sensitive)
  const deps = input.files.filter((file) => file.dependency)
  if (denied.length) review.push(`${denied.length} file(s) changed in denied paths: ${denied.slice(0, 5).map((file) => file.path).join(', ')}`)
  if (unexpected.length) review.push(`${unexpected.length} file(s) changed outside approved scope: ${unexpected.slice(0, 5).map((file) => file.path).join(', ')}`)
  if (sensitive.length) review.push(`sensitive surfaces changed: ${sensitive.slice(0, 5).map((file) => `${file.path} (${file.sensitive})`).join(', ')}`)
  if (deps.length) review.push(`dependency manifests or lockfiles changed: ${deps.slice(0, 5).map((file) => file.path).join(', ')}`)
  if (input.startDirty) review.push('the working tree was dirty at session start, so exact agent attribution is uncertain')
  const reviewFindings = input.findings.filter((finding) => severityRank[finding.severity] >= severityRank.MEDIUM && !blocking.includes(finding))
  if (reviewFindings.length) review.push(`${reviewFindings.length} medium-or-higher analyzer finding(s) affect changed files`)
  if (input.llm?.diffCoverage?.truncated) {
    review.push(`local ${input.llm.provider} review covered ${input.llm.diffCoverage.reviewedBytes} of ${input.llm.diffCoverage.totalBytes} diff bytes`)
  }
  if (input.llm?.verdict === 'review') review.push(`local ${input.llm.provider} review flagged possible slop or over-engineering`)
  if (!input.verifications.length) notes.push('no verification commands were configured')
  else if (!input.verifications.some((item) => item.exitCode !== 0)) notes.push(`all ${input.verifications.length} verification command(s) passed`)
  if (!input.files.length) notes.push('no repository files changed')
  else if (!denied.length && !unexpected.length) notes.push(`all ${input.files.length} changed file(s) are within approved scope`)
  if (failed.length) return { verdict: 'FAILED', reasons: [...failed, ...review] }
  if (review.length) return { verdict: 'REVIEW_REQUIRED', reasons: review }
  return { verdict: 'PASS', reasons: notes }
}

export function analyzerReceipt(
  analysis: Awaited<ReturnType<typeof analyzeRepository>>,
  _baseline?: Awaited<ReturnType<typeof analyzeRepository>>,
  delta?: FindingDelta,
): Receipt['analyzers'] {
  return {
    passes: analysis.passes,
    findings: delta ? [...delta.introduced, ...delta.worsened] : analysis.findings,
    analysisProfile: LOCAL_ANALYSIS_PROFILE,
    delta: delta ? {
      introduced: delta.introduced.length,
      worsened: delta.worsened.length,
      recurring: delta.recurring.length,
      resolved: delta.resolved.length,
    } : undefined,
    index: { totalLoc: analysis.index.totalLoc, languages: analysis.index.languages, primaryLanguage: analysis.index.primaryLanguage },
  }
}
