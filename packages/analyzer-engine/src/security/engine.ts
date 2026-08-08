import {
  sastLanguageForPath,
  MAX_NODES,
  type SastLanguage,
  type SastParser,
  type SyntaxNode,
} from './lang'
import {
  asCall,
  asFunction,
  identifierName,
  isTaggedTemplate,
  stringLiteralValue,
  urlHeadOf,
  walk,
  type NCall,
  type NFunc,
} from './normalize'
import {
  analyzeFunction,
  bindsToLocalFn,
  firstSource,
  hasRealSource,
  paramIndexes,
  soleParamOrigin,
  taintBudgetExhausted,
  taintOf,
  type FunctionTaint,
} from './taint'
import { PATTERN_RULES, TAINT_ASSIGN_SINKS, TAINT_SINKS, asNamedValue, ruleAppliesTo, type TaintAssignSink, type TaintSink } from './rules'
import { CWE } from './cwe'
import type { CodeLocation, Flow, SastDiagnostics, SastFinding, SastResult } from './types'

/**
 * The SAST engine: parse → taint → match rules → findings.
 *
 * Per file we run one taint solve per function, evaluate every call against the
 * taint sinks (direct findings + interprocedural param summaries), then a single
 * pattern-rule pass over the whole tree. Everything is bounded per file and the
 * whole thing is fail-soft: a parse error, a grammar that won't load, or a
 * runaway file degrades to fewer/zero findings for that file — never a thrown
 * scan. Absence of a finding is therefore never a proof of safety, which the
 * diagnostics make explicit.
 *
 * The parser is injected ({@link SastParser}) so the same rule pack runs behind
 * the hosted WASM grammars and behind the CLI's zero-dependency JS parser. A
 * language the injected parser does not cover is reported as degraded — the one
 * honest answer, and the reason a leaner parser can never turn into a wrong
 * finding.
 */

export interface ScanInput {
  filePath: string
  content: string
}

/** Rules this scan is allowed to report. Absent = the whole pack. */
export interface ScanOptions {
  /** Rule ids to keep. A rule outside the set never runs against a node. */
  ruleIds?: ReadonlySet<string>
  /** Per-file wall-clock ceiling. Defaults to {@link FILE_TIME_BUDGET_MS}. */
  fileTimeBudgetMs?: number
  /** Whole-pass wall-clock ceiling. Defaults to {@link PASS_TIME_BUDGET_MS}. */
  passTimeBudgetMs?: number
}

const MAX_FINDINGS_PER_FILE = 100
const MAX_FINDINGS_PER_SCAN = 100_000

/**
 * Wall-clock ceilings for the security pass.
 *
 * The node and taint budgets bound WORK, not TIME, and work is not a proxy for
 * time: one visit can cost microseconds or, on a pathological shape, orders of
 * magnitude more. Only a clock bounds the answer to "when does this finish".
 *
 * The numbers come from measurement, not taste. Over 8,976 files — CPython
 * 3.14's stdlib (1,852), its site-packages (6,449, including sympy and
 * pygments), and this repository's own `src/` (337) — the slowest single file
 * took 609 ms, p99 was 101 ms, and p50 was 3 ms. 5 s is ~8x the slowest file any
 * of those corpora produced, so nothing that completes today can trip it, while
 * a file that would otherwise run for minutes is cut in seconds. The whole
 * site-packages pass finishes in 63 s, so the 5-minute pass ceiling is ~5x the
 * largest corpus measured: a repository would need roughly 30,000 analyzable
 * files to approach it honestly.
 *
 * These are deliberately NOT determinism-preserving, and that is the trade:
 * identical output run-to-run is worth more than a scan that never returns, and
 * the moment a ceiling fires the diagnostics name the files it cut so the
 * result is read as partial rather than clean. A silent skip would be worse
 * than the hang it replaces.
 *
 * The hosted runner keeps its own, tighter job budget on top of these
 * (`runIsolatedSecurityScan`); these are the backstop for every in-process
 * caller — the CLI's local pass and the agent hooks — which had none.
 */
export const FILE_TIME_BUDGET_MS = 5_000
export const PASS_TIME_BUDGET_MS = 300_000

/** How many capped/skipped paths the diagnostics carry. The counts stay
 *  authoritative for the totals; this bounds only what gets named. */
const MAX_DISCLOSED_PATHS = 50

/**
 * A wall-clock ceiling that is cheap enough to consult per AST node.
 *
 * `Date.now()` per node measurably costs on a 400k-node tree, so the clock is
 * read once every {@link CLOCK_STRIDE} calls. Once expired it stays expired —
 * no further clock reads, and no chance of a ceiling "un-firing".
 */
const CLOCK_STRIDE = 512

function deadlineGate(deadline: number): () => boolean {
  // Starts at 1 so the FIRST consultation reads the clock: a budget already
  // spent when the file began must fire even on a file too small to reach the
  // stride. After that the stride amortizes the cost away.
  let countdown = 1
  let expired = false
  return () => {
    if (expired) return true
    if (--countdown > 0) return false
    countdown = CLOCK_STRIDE
    if (Date.now() < deadline) return false
    expired = true
    return true
  }
}

/** Scan a set of source files and return findings + honest diagnostics. */
export async function scanFiles(
  files: ScanInput[],
  parser: SastParser,
  options: ScanOptions = {},
): Promise<SastResult> {
  const findings: SastFinding[] = []
  let filesScanned = 0
  let filesSkipped = 0
  let truncatedFiles = 0
  let findingsTruncated = false
  const degraded = new Set<SastLanguage>()
  let timeCappedFiles = 0
  let timeSkippedFiles = 0
  let unparsedFiles = 0
  let erroredFiles = 0
  const timeCappedPaths: string[] = []
  const timeSkippedPaths: string[] = []
  const unparsedPaths: string[] = []
  const erroredPaths: string[] = []

  const fileBudgetMs = options.fileTimeBudgetMs ?? FILE_TIME_BUDGET_MS
  const passDeadline = Date.now() + (options.passTimeBudgetMs ?? PASS_TIME_BUDGET_MS)
  let passBudgetExceeded = false

  // web-tree-sitter grows its WASM heap while parsing and does not return that
  // high-water allocation to the host process between files. Continuing with
  // even a pattern-only parse after crossing the function budget can therefore
  // OOM the worker. Stop parsing new files once RSS crosses the limit, report
  // them as skipped, and let the scan authority layer withhold scores. This is
  // fail-closed: partial findings survive, but absence is never called clean.
  const configuredRssLimit = Number(process.env.SAST_TAINT_RSS_LIMIT_MB)
  const defaultRssLimit = process.env.NODE_ENV === 'test' ? Number.POSITIVE_INFINITY : 850
  const taintRssLimit =
    (Number.isFinite(configuredRssLimit) && configuredRssLimit > 0
      ? configuredRssLimit
      : defaultRssLimit) * 1048576
  let memoryLimitReached = false

  for (const file of files) {
    const lang = sastLanguageForPath(file.filePath)
    if (!lang) {
      filesSkipped++
      continue
    }
    if (memoryLimitReached || process.memoryUsage().rss > taintRssLimit) {
      memoryLimitReached = true
      filesSkipped++
      continue
    }
    // The pass ceiling. A file past it is not analyzed at all, and is named as
    // skipped rather than counted as scanned-and-clean.
    if (passBudgetExceeded || Date.now() >= passDeadline) {
      passBudgetExceeded = true
      filesSkipped++
      timeSkippedFiles++
      if (timeSkippedPaths.length < MAX_DISCLOSED_PATHS) timeSkippedPaths.push(file.filePath)
      continue
    }
    try {
      const fileFindings = await scanOne(
        file.filePath,
        file.content,
        lang,
        degraded,
        parser,
        options,
        // Never let one file spend the whole pass budget.
        Math.min(fileBudgetMs, passDeadline - Date.now()),
      )
      if (fileFindings === null) {
        filesSkipped++
        unparsedFiles++
        if (unparsedPaths.length < MAX_DISCLOSED_PATHS) unparsedPaths.push(file.filePath)
        continue
      }
      filesScanned++
      if (fileFindings.truncated) truncatedFiles++
      if (fileFindings.timeCapped) {
        timeCappedFiles++
        if (timeCappedPaths.length < MAX_DISCLOSED_PATHS) timeCappedPaths.push(file.filePath)
      }
      for (const f of fileFindings.findings) {
        if (findings.length >= MAX_FINDINGS_PER_SCAN) {
          findingsTruncated = true
          break
        }
        findings.push(f)
      }
      if (process.memoryUsage().rss > taintRssLimit) memoryLimitReached = true
    } catch {
      // never let one file crash the scan
      filesSkipped++
      erroredFiles++
      if (erroredPaths.length < MAX_DISCLOSED_PATHS) erroredPaths.push(file.filePath)
    }
  }

  dedupe(findings)
  sortFindings(findings)

  return {
    findings,
    diagnostics: {
      inputFiles: files.length,
      filesScanned,
      filesSkipped,
      degradedLanguages: [...degraded].sort(),
      truncatedFiles,
      findingsTruncated,
      resourceLimitReached: memoryLimitReached,
      ...(timeCappedFiles ? { timeCappedFiles, timeCappedPaths } : {}),
      ...(timeSkippedFiles ? { timeSkippedFiles, timeSkippedPaths } : {}),
      ...(unparsedFiles ? { unparsedFiles, unparsedPaths } : {}),
      ...(erroredFiles ? { erroredFiles, erroredPaths } : {}),
      ...(passBudgetExceeded ? { budgetExceeded: true } : {}),
    },
  }
}

/** Merge isolated batch results back into the same deterministic contract as a
 * single in-process scan. Each source file must belong to exactly one retained
 * batch result; callers discard a memory-truncated parent batch before retrying
 * its smaller children. */
export function mergeSastResults(results: SastResult[], inputFiles: number): SastResult {
  const findings = results.flatMap((result) => result.findings)
  dedupe(findings)
  sortFindings(findings)
  const findingsTruncated =
    results.some((result) => result.diagnostics.findingsTruncated) ||
    findings.length > MAX_FINDINGS_PER_SCAN
  if (findings.length > MAX_FINDINGS_PER_SCAN) findings.length = MAX_FINDINGS_PER_SCAN

  const degradedLanguages = new Set<SastLanguage>()
  let filesScanned = 0
  let filesSkipped = 0
  let truncatedFiles = 0
  let timeCappedFiles = 0
  let timeSkippedFiles = 0
  let unparsedFiles = 0
  let erroredFiles = 0
  const timeCappedPaths: string[] = []
  const timeSkippedPaths: string[] = []
  const unparsedPaths: string[] = []
  const erroredPaths: string[] = []
  for (const result of results) {
    filesScanned += result.diagnostics.filesScanned
    filesSkipped += result.diagnostics.filesSkipped
    truncatedFiles += result.diagnostics.truncatedFiles
    timeCappedFiles += result.diagnostics.timeCappedFiles ?? 0
    timeSkippedFiles += result.diagnostics.timeSkippedFiles ?? 0
    unparsedFiles += result.diagnostics.unparsedFiles ?? 0
    erroredFiles += result.diagnostics.erroredFiles ?? 0
    for (const language of result.diagnostics.degradedLanguages) degradedLanguages.add(language)
    for (const path of result.diagnostics.timeCappedPaths ?? []) {
      if (timeCappedPaths.length < MAX_DISCLOSED_PATHS) timeCappedPaths.push(path)
    }
    for (const path of result.diagnostics.timeSkippedPaths ?? []) {
      if (timeSkippedPaths.length < MAX_DISCLOSED_PATHS) timeSkippedPaths.push(path)
    }
    for (const path of result.diagnostics.unparsedPaths ?? []) {
      if (unparsedPaths.length < MAX_DISCLOSED_PATHS) unparsedPaths.push(path)
    }
    for (const path of result.diagnostics.erroredPaths ?? []) {
      if (erroredPaths.length < MAX_DISCLOSED_PATHS) erroredPaths.push(path)
    }
  }
  timeCappedPaths.sort()
  timeSkippedPaths.sort()
  unparsedPaths.sort()
  erroredPaths.sort()

  return {
    findings,
    diagnostics: {
      inputFiles,
      filesScanned,
      filesSkipped,
      degradedLanguages: [...degradedLanguages].sort(),
      truncatedFiles,
      findingsTruncated,
      resourceLimitReached: results.some((result) => result.diagnostics.resourceLimitReached),
      budgetExceeded: results.some((result) => result.diagnostics.budgetExceeded),
      ...(timeCappedFiles ? { timeCappedFiles, timeCappedPaths } : {}),
      ...(timeSkippedFiles ? { timeSkippedFiles, timeSkippedPaths } : {}),
      ...(unparsedFiles ? { unparsedFiles, unparsedPaths } : {}),
      ...(erroredFiles ? { erroredFiles, erroredPaths } : {}),
      failureReason: results.find((result) => result.diagnostics.failureReason)?.diagnostics.failureReason,
    },
  }
}

interface FileScan {
  findings: SastFinding[]
  truncated: boolean
  /** The per-file wall-clock ceiling fired: analysis of this file is partial. */
  timeCapped: boolean
}

/**
 * The sentence a receipt or a hosted report prints when a wall-clock ceiling
 * fired — naming the files, not just counting them.
 *
 * One function so the CLI receipt and the hosted report say the SAME thing in
 * the same voice. A timeout that quietly produced "no findings" would be worse
 * than the hang it replaced, so the wording is explicit that a file the clock
 * cut was not cleared: silence about it is missing evidence, not absence of a
 * defect. Returns undefined when no ceiling fired, so callers can spread it.
 */
export function timeCeilingDisclosure(diagnostics: SastDiagnostics): string | undefined {
  const parts: string[] = []
  const capped = diagnostics.timeCappedFiles ?? 0
  const skipped = diagnostics.timeSkippedFiles ?? 0
  if (capped > 0) {
    parts.push(
      // "a time ceiling", not "the per-file ceiling": a file that starts just
      // before the pass deadline is cut by the pass budget through the same
      // gate, and the sentence has to stay true in both cases.
      `a time ceiling stopped security analysis partway through ${capped} file(s) — ` +
        `${namePaths(diagnostics.timeCappedPaths ?? [], capped)}; the rules that had not run there reported nothing, ` +
        `which is not the same as finding nothing`,
    )
  }
  if (skipped > 0) {
    parts.push(
      `the whole-pass time ceiling was reached and ${skipped} file(s) were not analyzed at all — ` +
        `${namePaths(diagnostics.timeSkippedPaths ?? [], skipped)}`,
    )
  }
  return parts.length > 0 ? parts.join('; ') : undefined
}

/**
 * The sentence a receipt prints when the parser could not read a file — naming
 * it, and naming the limitation as OURS.
 *
 * A file we cannot parse is a gap in our grammar, not a defect in the reader's
 * code, and the wording has to survive being read by someone whose perfectly
 * valid source we just declined to analyze. Counting without naming is the
 * failure mode this replaces: "1 file(s) could not be parsed" tells a reader
 * that something is wrong and gives them no way to find it, act on it, or
 * disagree with it.
 *
 * Returns undefined when every file parsed, so callers can spread it.
 */
export function parseFailureDisclosure(diagnostics: SastDiagnostics): string | undefined {
  const parts: string[] = []
  const unparsed = diagnostics.unparsedFiles ?? 0
  const errored = diagnostics.erroredFiles ?? 0
  if (unparsed > 0) {
    const languages = diagnostics.degradedLanguages
    parts.push(
      `the local parser could not read ${unparsed} file(s), so no security rule ran over them — ` +
        `${namePaths(diagnostics.unparsedPaths ?? [], unparsed)}` +
        `${languages.length ? ` (${languages.join(', ')})` : ''}; ` +
        'this is a limit of the bundled grammar, not a defect in those files',
    )
  }
  if (errored > 0) {
    parts.push(
      `security analysis threw partway through ${errored} file(s) and reported nothing for them — ` +
        `${namePaths(diagnostics.erroredPaths ?? [], errored)}`,
    )
  }
  return parts.length > 0 ? parts.join('; ') : undefined
}

/** Name the paths we kept, and say plainly how many we did not keep. */
function namePaths(paths: string[], total: number): string {
  if (paths.length === 0) return 'their paths were not retained'
  const rest = total - paths.length
  return paths.join(', ') + (rest > 0 ? `, and ${rest} more` : '')
}

/** Which param indexes of a local function reach which sink. */
interface ParamSinkRecord {
  sink: TaintSink
  node: SyntaxNode
  line: number
}
interface FnRecord {
  fn: NFunc
  ft: FunctionTaint
  /** param index → the sink it reaches (first wins). */
  sinkParams: Map<number, ParamSinkRecord>
}

async function scanOne(
  filePath: string,
  content: string,
  lang: SastLanguage,
  degraded: Set<SastLanguage>,
  parser: SastParser,
  options: ScanOptions,
  timeBudgetMs: number,
): Promise<FileScan | null> {
  // The clock starts before the parse, so a slow parse eats into this file's
  // own budget rather than escaping the ceiling.
  const outOfTime = deadlineGate(Date.now() + timeBudgetMs)
  const parsed = await parser.parse(lang, content)
  if (!parsed) {
    degraded.add(lang)
    return null
  }

  const lines = content.split('\n')
  const loc = (node: SyntaxNode, label: string): CodeLocation & { label: string } => ({
    filePath,
    line: node.startPosition.row + 1,
    column: node.startPosition.column + 1,
    snippet: snippetAt(lines, node.startPosition.row),
    label,
  })

  const findings: SastFinding[] = []
  /** Sinks whose whole dangerous argument is a parameter — see {@link resolveCallerSupplied}. */
  const callerSupplied: CallerSuppliedCandidate[] = []
  const enabled = (id: string) => !options.ruleIds || options.ruleIds.has(id)
  const applicableSinks = TAINT_SINKS.filter((s) => ruleAppliesTo(s, lang) && enabled(s.id))
  const applicablePatterns = PATTERN_RULES.filter((p) => ruleAppliesTo(p, lang) && enabled(p.id))
  const applicableAssignSinks = TAINT_ASSIGN_SINKS.filter((s) => ruleAppliesTo(s, lang) && enabled(s.id))

  let nodeCount = 0
  let truncated = false
  let timeCapped = false
  // Consulted at every phase boundary and inside every walk. Once it fires the
  // remaining phases short-circuit: partial findings are kept and the file is
  // reported as capped, never as a fully-analyzed file with nothing in it.
  const expired = () => {
    if (!outOfTime()) return false
    timeCapped = true
    return true
  }

  // ---- gather functions & solve taint per function ----
  const fnRecords: FnRecord[] = []
  walk(parsed.rootNode, (node) => {
    if (++nodeCount > MAX_NODES) {
      truncated = true
      return
    }
    if (expired()) return
    const fn = asFunction(node, lang)
    if (fn && fn.body) {
      const ft = analyzeFunction(fn, lang)
      fnRecords.push({ fn, ft, sinkParams: new Map() })
    }
  })

  // ---- direct sink findings + build interprocedural summaries ----
  for (const rec of fnRecords) {
    if (!rec.fn.body) continue
    if (expired()) break
    walk(rec.fn.body, (node) => {
      if (findings.length >= MAX_FINDINGS_PER_FILE) return
      if (expired()) return
      if (isNestedFnBoundary(node, rec.fn, lang)) return
      // Assignment-shaped sinks (XSS): `__html:` is a JSX pair and
      // `el.innerHTML =` an assignment, so neither reaches a call-based rule.
      for (const sink of applicableAssignSinks) {
        const nv = asNamedValue(node, lang)
        if (!nv || !sink.matchName(nv.name)) continue
        if (sink.sites && !sink.sites.has(node.type)) continue
        if (sink.safeValue?.(nv.value, lang)) continue
        // Head-position sinks (open redirect): taint confined to a path segment
        // of an origin-relative target cannot steer the victim off-origin.
        if (sink.taintPosition === 'head' && headTaintSuppressed(nv.value, rec.ft, lang)) continue
        const origins = taintOf(nv.value, rec.ft)
        if (!hasRealSource(origins)) continue
        const src = firstSource(origins)!
        findings.push(makeAssignFinding(sink, lang, filePath, nv.node, src.node, src.sourceKind, loc, lines))
      }
      const call = asCall(node, lang)
      if (!call) return
      for (const sink of applicableSinks) {
        const idxs = sink.match(call, lang)
        if (!idxs) continue
        for (const i of idxs) {
          const arg = call.args[i]
          if (!arg) continue
          const origins = taintOf(arg, rec.ft)
          if (origins.length === 0) continue
          // Head-position sinks (SSRF): taint confined to path/query segments
          // of a constant-authority URL cannot steer the request target.
          if (sink.taintPosition === 'head' && headTaintSuppressed(arg, rec.ft, lang)) continue
          if (hasRealSource(origins)) {
            const src = firstSource(origins)!
            findings.push(makeTaintFinding(sink, lang, filePath, call, src.node, src.sourceKind, false, loc, lines))
          } else if (sink.callerSuppliedArg?.appliesTo(call, lang)) {
            // The argument IS one of this function's parameters, named: not a
            // local built from one. The distinction is the whole precision of
            // this report and the corpus found it — firecrawl's
            // `services/worker/nuq.ts:1028` passes a local `query` assembled
            // from a template two lines above, whose only taint origin happens
            // to be a parameter. Nobody supplies that string; the file builds
            // it, in view, so "supplied by the caller" would be false about it.
            // Requiring the identifier to be the parameter itself keeps this to
            // the case where the file performs no query construction at all.
            //
            // Held back until every call site is known — a same-file caller
            // binding a literal or a tagged template answers the question the
            // finding would ask.
            //
            // An anonymous enclosing function is skipped outright. The
            // suppression below resolves call sites BY NAME, so a nameless
            // function can never be shown to be constrained and would report
            // unconditionally — `const run = (sql) => pool.query(sql)` beside
            // `run('SELECT 1')` is safe and would fire. Stated recall cost:
            // this report never reaches an arrow assigned to a variable.
            const param = soleParamOrigin(origins)
            if (param && rec.fn.name !== ANONYMOUS_FN && identifierName(arg, lang) === param.name) {
              callerSupplied.push({ sink, call, fn: rec.fn, paramIndex: param.index, paramName: param.name })
            }
          }
          for (const pi of paramIndexes(origins)) {
            if (!rec.sinkParams.has(pi)) rec.sinkParams.set(pi, { sink, node: call.node, line: call.line })
          }
        }
        break // one sink per call site
      }
    })
  }

  // ---- one-hop interprocedural: tainted arg → param that reaches a sink ----
  const summaries = new Map<string, FnRecord>()
  for (const rec of fnRecords) {
    if (rec.sinkParams.size > 0 && !summaries.has(rec.fn.name)) summaries.set(rec.fn.name, rec)
  }
  if (summaries.size > 0) {
    for (const rec of fnRecords) {
      if (!rec.fn.body) continue
      if (expired()) break
      walk(rec.fn.body, (node) => {
        if (findings.length >= MAX_FINDINGS_PER_FILE) return
        if (expired()) return
        const call = asCall(node, lang)
        if (!call || call.isConstruct) return
        if (!bindsToLocalFn(call)) return // don't bind a member call to a same-name local fn
        const target = summaries.get(call.method)
        if (!target || target.fn === rec.fn) return
        for (const [pi, record] of target.sinkParams) {
          const arg = call.args[pi]
          if (!arg) continue
          const origins = taintOf(arg, rec.ft)
          const src = firstSource(origins)
          if (!src) continue
          findings.push(
            makeInterprocFinding(record.sink, lang, filePath, call, target.fn, record, src.node, src.sourceKind, loc, lines),
          )
        }
      })
    }
  }

  // ---- caller-supplied SQL text ----
  if (callerSupplied.length > 0 && !expired()) {
    resolveCallerSupplied(callerSupplied, parsed.rootNode, lang, filePath, findings, loc, lines, expired)
  }

  // ---- pattern rules (single pass over the whole tree) ----
  runPatternRules(parsed.rootNode, applicablePatterns, lang, filePath, findings, lines, expired)

  parsed.release()
  // A drained taint budget means some solve or sink query degraded to
  // no-taint — real coverage loss, same as the node budget. A tree with error
  // nodes (parsed.hasError) is still fully walked best-effort, and the
  // per-file findings cap only bounds OUTPUT — neither degrades coverage.
  if (fnRecords.some((rec) => taintBudgetExhausted(rec.ft))) truncated = true
  // A time-capped file is the same coverage loss as a node-budget one, so it
  // rides the SAME `truncated` path every consumer already handles. The
  // separate flag only lets the caller name it.
  if (timeCapped) truncated = true
  return { findings, truncated, timeCapped }
}

/** What {@link asFunction} names a function whose node carries no `name` field. */
const ANONYMOUS_FN = '<anonymous>'

/** A sink argument that is exactly one of the enclosing function's parameters. */
interface CallerSuppliedCandidate {
  sink: TaintSink
  call: NCall
  fn: NFunc
  paramIndex: number
  paramName: string
}

/**
 * Decide which caller-supplied-argument candidates survive, and report them.
 *
 * The question a candidate asks is "what can a caller put here?", so the answer
 * lives at the call sites. One same-file call binding a safe construction —
 * a string literal, or a tagged template whose interpolations are bound values —
 * shows the file DOES constrain the parameter, and the candidate is dropped.
 * A function nothing in this file calls keeps its finding: its callers are
 * outside the translation unit, which is precisely why the value is unknown.
 *
 * Call sites are matched by name under the same rule as the interprocedural hop
 * ({@link bindsToLocalFn}): a direct call, or `this`/`self`. A member call on
 * any other receiver is a different function that merely shares a name.
 */
function resolveCallerSupplied(
  candidates: CallerSuppliedCandidate[],
  root: SyntaxNode,
  lang: SastLanguage,
  filePath: string,
  findings: SastFinding[],
  loc: (n: SyntaxNode, label: string) => CodeLocation & { label: string },
  lines: string[],
  expired: () => boolean,
): void {
  const wanted = new Set(candidates.map((c) => c.fn.name))
  /** `${fnName}#${paramIndex}` for every parameter a call site binds safely. */
  const constrained = new Set<string>()
  walk(root, (node) => {
    if (expired()) return
    const call = asCall(node, lang)
    if (!call || call.isConstruct || !wanted.has(call.method) || !bindsToLocalFn(call)) return
    call.args.forEach((arg, i) => {
      if (stringLiteralValue(arg, lang) !== null || isTaggedTemplate(arg, lang)) {
        constrained.add(`${call.method}#${i}`)
      }
    })
  })
  // A drained clock means the call-site sweep is incomplete, so "no call site
  // constrains it" is unproven. Report nothing rather than report on a partial
  // answer; the file is already marked truncated.
  if (expired()) return
  const seen = new Set<number>()
  for (const candidate of candidates) {
    if (findings.length >= MAX_FINDINGS_PER_FILE) return
    if (constrained.has(`${candidate.fn.name}#${candidate.paramIndex}`)) continue
    if (seen.has(candidate.call.node.id)) continue
    seen.add(candidate.call.node.id)
    findings.push(makeCallerSuppliedFinding(candidate, lang, filePath, loc, lines))
  }
}

function makeCallerSuppliedFinding(
  candidate: CallerSuppliedCandidate,
  lang: SastLanguage,
  filePath: string,
  loc: (n: SyntaxNode, label: string) => CodeLocation & { label: string },
  lines: string[],
): SastFinding {
  const { sink, call, fn, paramName } = candidate
  const report = sink.callerSuppliedArg!
  const info = CWE[sink.cweKey]
  const source = loc(fn.node, `${fn.name}(${paramName}) — supplied by the caller`)
  const sinkLoc = loc(call.node, `${call.fullName}()`)
  return {
    ruleId: sink.id,
    kind: 'taint',
    cwe: info.cwe,
    owasp: info.owasp,
    severity: report.severity,
    title: sink.title,
    message: report.message(fn.name, paramName),
    language: lang,
    filePath,
    line: call.line,
    column: call.node.startPosition.column + 1,
    flow: {
      source,
      sink: sinkLoc,
      steps: [source, sinkLoc],
      summary: `${fn.name}(${paramName}) → ${call.fullName}()`,
      interprocedural: false,
    },
    remediation: report.remediation,
    metadata: sortMeta({
      callerSupplied: true,
      parameter: paramName,
      sink: call.fullName,
      snippet: snippetAt(lines, call.line - 1),
    }),
  }
}

/** Pattern-rule pass over a tree. Cheap (no taint), so it always runs even when
 *  the taint solve is skipped under memory pressure. */
function runPatternRules(
  root: SyntaxNode,
  patterns: typeof PATTERN_RULES,
  lang: SastLanguage,
  filePath: string,
  findings: SastFinding[],
  lines: string[],
  expired: () => boolean,
): void {
  // Per-rule path exclusion (seed/migration/ops directories where the pattern
  // is expected and harmless) — resolved once per file, not per node.
  const activePatterns = patterns.filter((rule) => !rule.excludePath || !rule.excludePath.test(filePath))
  walk(root, (node) => {
    if (findings.length >= MAX_FINDINGS_PER_FILE) return
    if (expired()) return
    for (const rule of activePatterns) {
      for (const hit of rule.test(node, lang)) {
        const info = CWE[rule.cweKey]
        findings.push({
          ruleId: rule.id,
          kind: 'pattern',
          cwe: info.cwe,
          owasp: info.owasp,
          severity: rule.severity,
          title: rule.title,
          message: rule.message,
          language: lang,
          filePath,
          line: hit.line,
          column: hit.node.startPosition.column + 1,
          remediation: rule.remediation,
          metadata: sortMeta({ detail: hit.detail, snippet: snippetAt(lines, hit.line - 1) }),
        })
      }
    }
  })
}

/** A finding for a nested function is handled by that function's own record. */
function isNestedFnBoundary(node: SyntaxNode, fn: NFunc, lang: SastLanguage): boolean {
  return node !== fn.node && node !== fn.body && asFunction(node, lang) !== null
}

/** Constant URL head that pins scheme + authority (`scheme://host/…`) — taint
 *  after it can only land in the path/query/fragment. */
const AUTHORITY_PINNED_PREFIX = /^[a-z][a-z0-9+.-]*:\/\/[^\/?#]+[\/?#]/i
/** Single-slash relative path with a constant character after the slash. A
 *  lone '/' does NOT qualify: taint abutting it becomes `//host`, which
 *  fetch/axios treat as protocol-relative and follow off-origin. */
const SINGLE_SLASH_PATH = /^\/[^\/]/
/** Constant fragment after the head expression that ends the authority: a
 *  single '/' starts the path, and '?' or '#' start the query/fragment — past
 *  any of them a tainted part cannot reach the host. A fragment that is empty
 *  or starts with ':' or '//' leaves the following part in scheme/authority
 *  position (`${scheme}://${host}`) and must NOT anchor. */
const PATH_ANCHOR = /^(\/(?!\/)|[?#])/
/** A scheme/protocol-relative opener (`http://`, `http://a`, `//`) — when the
 *  authority-pinning match above failed, the host is still attacker-extendable. */
const AUTHORITY_OPENER = /^([a-z][a-z0-9+.-]*:)?\/\//i

/**
 * The relative reference of `new URL(reference, base)`, or null when the shape
 * does not apply.
 *
 * WHATWG resolution makes the base supply the origin for every reference that
 * is not itself absolute, so the origin-position question collapses onto the
 * FIRST argument and the base drops out: `new URL('/booking/' + uid, WEBAPP_URL)`
 * lands on WEBAPP_URL's origin no matter what `uid` holds. A single argument is
 * not this shape — there is no base, so that argument is the whole URL.
 *
 * The base is not re-examined, matching the constant-first-argument carve-out
 * in `evalOrigins`: `new URL('/login', req.url)` is the Next.js middleware
 * idiom, and the same trade-off (a host injection through an attacker-chosen
 * base is suppressed too) is accepted here for the same reason.
 */
function urlBaseRelativeReference(arg: SyntaxNode, lang: SastLanguage): SyntaxNode | null {
  const call = asCall(arg, lang)
  if (!call || !call.isConstruct || call.fullName.toLowerCase() !== 'url') return null
  return call.args.length >= 2 ? call.args[0] ?? null : null
}

/**
 * Position-aware suppression for head-position sinks (SSRF, open redirect). A
 * URL built as a template/concat is only attacker-steerable when taint can
 * reach its scheme/authority: suppress when a constant head pins the authority
 * (or is a single-slash relative path), or when the head expression is
 * untainted (e.g. a `${BASE}` config var) and every tainted part lands after a
 * path-anchoring constant fragment. Deliberately conservative — an empty,
 * protocol-relative ('//') or incomplete-host ('http://', 'http://a') prefix,
 * or a tainted head, still flags, and a non-template/concat argument is never
 * suppressed.
 */
function headTaintSuppressed(arg: SyntaxNode, ft: FunctionTaint, lang: SastLanguage, depth = 0): boolean {
  // `new URL(ref, base)` — ask the same question of `ref`, which is what decides
  // whether the base's origin survives. A reference that opens its own authority
  // ('//host', 'https://host') fails the checks below exactly as it should.
  const reference = depth < 4 ? urlBaseRelativeReference(arg, lang) : null
  if (reference) return headTaintSuppressed(reference, ft, lang, depth + 1)
  const { constantPrefix, headExpr, parts } = urlHeadOf(arg, lang)
  if (!parts) return false // opaque expression — the whole argument is the URL
  if (constantPrefix !== null && (AUTHORITY_PINNED_PREFIX.test(constantPrefix) || SINGLE_SLASH_PATH.test(constantPrefix))) {
    return true
  }
  // An unclosed authority in the constant head ('http://a…') means whatever
  // follows extends the HOST, not the path — never suppress.
  if (constantPrefix && AUTHORITY_OPENER.test(constantPrefix)) return false
  if (headExpr && taintOf(headExpr, ft).length > 0) return false // taint steers the authority
  // A tainted part is harmless only once a constant fragment AFTER the head
  // expression path-anchors it. A connecting fragment that could still place
  // the tainted part in scheme/authority position — empty, ':', '//', '://' —
  // must not suppress (`${scheme}://${req.query.host}/x` steers the HOST).
  let pastHead = false
  let pathAnchored = false
  for (const part of parts) {
    if (part.kind === 'const') {
      if (pastHead && PATH_ANCHOR.test(part.text)) pathAnchored = true
    } else if (part.node === headExpr) {
      pastHead = true
    } else if (!pathAnchored && taintOf(part.node, ft).length > 0) {
      return false
    }
  }
  return true
}

function makeTaintFinding(
  sink: TaintSink,
  lang: SastLanguage,
  filePath: string,
  call: NCall,
  sourceNode: SyntaxNode,
  sourceKind: string,
  interprocedural: boolean,
  loc: (n: SyntaxNode, label: string) => CodeLocation & { label: string },
  lines: string[],
): SastFinding {
  const info = CWE[sink.cweKey]
  const source = loc(sourceNode, `untrusted input (${sourceKind})`)
  const sinkLoc = loc(call.node, `${call.fullName}()`)
  const flow: Flow = {
    source,
    sink: sinkLoc,
    steps: [source, sinkLoc],
    summary: `${sourceKind} → ${call.fullName}()`,
    interprocedural,
  }
  // A same-line source→sink is one expression, not a two-hop journey.
  const sameLine = source.filePath === sinkLoc.filePath && source.line === sinkLoc.line
  return {
    ruleId: sink.id,
    kind: 'taint',
    cwe: info.cwe,
    owasp: info.owasp,
    severity: sink.severity,
    title: sink.title,
    message: sameLine
      ? `${sink.message} Untrusted data from ${sourceKind} reaches ${call.fullName}() in the same expression (line ${sinkLoc.line}).`
      : `${sink.message} Untrusted data from ${sourceKind} (line ${source.line}) reaches ${call.fullName}() at line ${sinkLoc.line}.`,
    language: lang,
    filePath,
    line: call.line,
    column: call.node.startPosition.column + 1,
    flow,
    remediation: sink.remediation,
    metadata: sortMeta({ sourceKind, sink: call.fullName, snippet: snippetAt(lines, call.line - 1) }),
  }
}

/** Finding for an assignment-shaped sink, where the location is the binding. */
function makeAssignFinding(
  sink: TaintAssignSink,
  lang: SastLanguage,
  filePath: string,
  sinkNode: SyntaxNode,
  sourceNode: SyntaxNode,
  sourceKind: string,
  loc: (n: SyntaxNode, label: string) => CodeLocation & { label: string },
  lines: string[],
): SastFinding {
  const info = CWE[sink.cweKey]
  const source = loc(sourceNode, `untrusted input (${sourceKind})`)
  const sinkLoc = loc(sinkNode, sink.title)
  const flow: Flow = {
    source,
    sink: sinkLoc,
    steps: [source, sinkLoc],
    summary: `${sourceKind} -> ${sink.surface}`,
    interprocedural: false,
  }
  const sameLine = source.filePath === sinkLoc.filePath && source.line === sinkLoc.line
  return {
    ruleId: sink.id,
    kind: 'taint',
    cwe: info.cwe,
    owasp: info.owasp,
    severity: sink.severity,
    title: sink.title,
    message: sameLine
      ? `${sink.message} Untrusted data from ${sourceKind} is assigned to ${sink.surface} in the same expression (line ${sinkLoc.line}).`
      : `${sink.message} Untrusted data from ${sourceKind} (line ${source.line}) is assigned to ${sink.surface} at line ${sinkLoc.line}.`,
    language: lang,
    filePath,
    line: sinkLoc.line,
    column: sinkNode.startPosition.column + 1,
    flow,
    remediation: sink.remediation,
    metadata: sortMeta({ sourceKind, sink: sink.surface, snippet: snippetAt(lines, sinkLoc.line - 1) }),
  }
}

function makeInterprocFinding(
  sink: TaintSink,
  lang: SastLanguage,
  filePath: string,
  call: NCall,
  callee: NFunc,
  record: ParamSinkRecord,
  sourceNode: SyntaxNode,
  sourceKind: string,
  loc: (n: SyntaxNode, label: string) => CodeLocation & { label: string },
  lines: string[],
): SastFinding {
  const info = CWE[sink.cweKey]
  const source = loc(sourceNode, `untrusted input (${sourceKind})`)
  const callSite = loc(call.node, `${call.method}(…) → ${callee.name}()`)
  const sinkLoc = loc(record.node, `${sink.title} in ${callee.name}()`)
  const flow: Flow = {
    source,
    sink: sinkLoc,
    steps: [source, callSite, sinkLoc],
    summary: `${sourceKind} → ${callee.name}(…) → sink in ${callee.name}() (line ${sinkLoc.line})`,
    interprocedural: true,
  }
  return {
    ruleId: sink.id,
    kind: 'taint',
    cwe: info.cwe,
    owasp: info.owasp,
    severity: sink.severity,
    title: sink.title,
    message: `${sink.message} Untrusted data from ${sourceKind} (line ${source.line}) is passed to ${callee.name}() and reaches ${sink.title.toLowerCase()} at line ${sinkLoc.line}.`,
    language: lang,
    filePath,
    line: call.line,
    column: call.node.startPosition.column + 1,
    flow,
    remediation: sink.remediation,
    metadata: sortMeta({ sourceKind, callee: callee.name, sinkLine: sinkLoc.line, snippet: snippetAt(lines, call.line - 1) }),
  }
}

function snippetAt(lines: string[], row: number): string | undefined {
  const raw = lines[row]
  if (raw === undefined) return undefined
  const trimmed = raw.trim()
  return trimmed.length > 200 ? trimmed.slice(0, 200) + '…' : trimmed
}

/** Deterministic metadata ordering so findings serialize identically each run. */
function sortMeta(meta: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const k of Object.keys(meta).sort()) {
    if (meta[k] !== undefined) out[k] = meta[k]
  }
  return out
}

const SEV_RANK: Record<SastFinding['severity'], number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

/** Stable, severity-then-location ordering — deterministic across runs. */
function sortFindings(findings: SastFinding[]): void {
  findings.sort(
    (a, b) =>
      SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
      a.filePath.localeCompare(b.filePath) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId) ||
      (a.column ?? 0) - (b.column ?? 0),
  )
}

/** Collapse identical (rule, file, line) findings that different passes emit. */
function dedupe(findings: SastFinding[]): void {
  const seen = new Set<string>()
  let w = 0
  for (let r = 0; r < findings.length; r++) {
    const f = findings[r]
    const key = `${f.ruleId}|${f.filePath}|${f.line}|${f.column ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    findings[w++] = f
  }
  findings.length = w
}
