export type FindingCategory =
  | 'TECH_DEBT'
  | 'BUG_RISK'
  | 'DEAD_CODE'
  | 'DUPLICATION'
  | 'SECURITY_HYGIENE'
  | 'DOCUMENTATION'
  | 'ARCHITECTURE'
  | 'TESTING'
  | 'DEPENDENCY'
  | 'PERFORMANCE'
  | 'STRUCTURE'
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface FrameworkSignal {
  name: string
  evidence: string
}
export type RepoType = 'library' | 'application'

export interface IndexedFile {
  path: string
  language: string | null
  kind: string
  sizeBytes: number
  loc: number
  sha: string | null
  content: string | null
  /**
   * Text of a file the indexer excluded from analysis by classification
   * (generated, minified). `content` stays null so LOC totals, the knowledge
   * graph, and every quality analyzer keep skipping it — that exclusion exists
   * to stop machine-written output from producing spurious findings.
   *
   * Secret scanning is the one pass that must never be exempted by provenance:
   * a committed credential is a credential whether or not a generator wrote the
   * line, so `secretsAnalyzer` reads this instead.
   */
  excludedContent?: string | null
}

export interface IndexCoverage {
  discoveredFiles: number
  maxFiles: number
  truncated: boolean
  textCandidates: number
  contentLoaded: number
  oversizedTextFiles: number
  unreadableTextFiles: number
  binaryTextFiles: number
}

export interface RepoIndex {
  root: string
  files: IndexedFile[]
  languages: Record<string, number>
  frameworks: FrameworkSignal[]
  packageManagers: string[]
  databases: string[]
  dependencies: Set<string>
  totalLoc: number
  primaryLanguage: string | null
  repoType: RepoType
  vendoredDirs: Record<string, number>
  generatedFiles?: Record<string, number>
  coverage?: IndexCoverage
}

/**
 * A concrete, reviewable change that would resolve one finding.
 *
 * SUGGESTION ONLY. CodeTruss never applies, writes, or executes it, and never
 * presents it as required — a change derived from a single matched line cannot
 * know the rest of the codebase. An analyzer attaches one only when the
 * finding's own evidence (path, line, matched text, index facts) makes the
 * change correct for that exact instance. When the right fix is ambiguous the
 * prose `suggestion` stays the whole answer and no `fix` is attached: a wrong
 * autofix is a false positive with extra damage.
 */
export interface FindingFix {
  /** What the change does, in one line. */
  description: string
  /** `diff` is unified-diff text; `snippet` is replacement or starter content. */
  kind: 'diff' | 'snippet'
  /** Fenced-code language for rendering — `diff`, `sh`, `yaml`, `markdown`, … */
  language: string
  /** The suggested text itself. */
  content: string
  /** What the reader must confirm before applying. Never empty. */
  safetyNote: string
}

/**
 * A developer's inline judgement that one finding is wrong, read from a
 * `codetruss-ignore: <reason>` comment beside the code. See `suppression.ts`.
 *
 * Attached to the finding rather than replacing it. A suppressed finding is
 * still produced, still counted in the delta, and still written to the receipt
 * — as suppressed, with its reason. Deleting it instead would let a comment in
 * the repository decide what the signed evidence is allowed to say.
 */
export interface FindingSuppression {
  /** The text after `codetruss-ignore:`. Empty only when `applied` is false. */
  reason: string
  /** 1-based line carrying the marker: the finding's own line, or the one above. */
  markerLine: number
  /**
   * Whether the marker actually dismissed this finding. False for a marker that
   * gave no reason — the finding stays reported, and the rejected marker is
   * disclosed so a comment is never seen to fail in silence.
   */
  applied: boolean
}

export interface AnalyzerFinding {
  category: FindingCategory
  severity: FindingSeverity
  title: string
  description: string
  filePath?: string
  line?: number
  suggestion?: string
  /** Optional ready-to-review change. Absent whenever the correct fix is ambiguous. */
  fix?: FindingFix
  impactScore: number
  effort?: 'low' | 'medium' | 'high'
  metadata?: Record<string, unknown>
  analyzerId?: string
  /** Present only when an inline marker was found beside this finding. */
  suppression?: FindingSuppression
}

export interface AnalyzerRunResult {
  findings: AnalyzerFinding[]
  complete: boolean
  truncated?: boolean
  detail?: string
  metrics?: Record<string, string | number | boolean | null>
}

const COMPLETION = Symbol('codetruss.analyzer-completion')
type FindingList = AnalyzerFinding[] & { [COMPLETION]?: Omit<AnalyzerRunResult, 'findings'> }

export function incompleteAnalyzerOutput(
  findings: AnalyzerFinding[],
  status: Omit<AnalyzerRunResult, 'findings' | 'complete'>,
): AnalyzerFinding[] {
  Object.defineProperty(findings, COMPLETION, {
    value: { ...status, complete: false },
    enumerable: false,
  })
  return findings
}

export function annotatedAnalyzerOutput(
  findings: AnalyzerFinding[],
  status: Omit<AnalyzerRunResult, 'findings' | 'complete' | 'truncated'>,
): AnalyzerFinding[] {
  Object.defineProperty(findings, COMPLETION, {
    value: { ...status, complete: true },
    enumerable: false,
  })
  return findings
}

export function analyzerResult(output: AnalyzerFinding[]): AnalyzerRunResult {
  const status = (output as FindingList)[COMPLETION]
  return { findings: output, complete: status?.complete ?? true, ...status }
}

/**
 * Which passes OUTSIDE the registry run alongside the analyzers in this
 * execution. The registry is shared, but the passes around it are not: the
 * hosted pipeline runs SAST for the scan types whose policy includes it, and
 * the local CLI never runs it at all. An analyzer that discloses coverage has
 * to be told, because "the SAST engine covers TypeScript" is a fact about the
 * engine, not about this run.
 */
export interface AnalyzerContext {
  /** The SAST pass (security rules + taint tracking) runs for this analysis. */
  sast: boolean
  /**
   * Vulnerability classes the SAST pass did NOT check in this analysis, when it
   * ran with a reduced rule set.
   *
   * The CLI runs a precision-validated SUBSET of the rule pack behind its
   * zero-dependency parser: real injection and AI-agent-defect coverage, but not
   * the classes that still need the hosted graph. "The pass ran" and "every
   * class was checked" are different claims, and a receipt that conflated them
   * would be the same blind spot the coverage analyzer exists to close — just
   * one level down.
   */
  sastUncheckedClasses?: readonly string[]
}

/**
 * Fail-honest default: a caller that does not declare its non-registry passes
 * is treated as running none of them. A front-end that omits the declaration
 * therefore over-discloses rather than inheriting a caveat written for a pass
 * it never executes.
 */
export const REGISTRY_ONLY_ANALYSIS: AnalyzerContext = { sast: false }

export interface Analyzer {
  id: string
  name: string
  description: string
  run(index: RepoIndex, context?: AnalyzerContext): Promise<AnalyzerFinding[]>
}
