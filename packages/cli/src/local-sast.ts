import type { AnalyzerFinding, AnalyzerPass, RepoIndex } from '@codetruss/analyzer-engine'
import {
  mergeSastResults,
  scanFiles,
  timeCeilingDisclosure,
  type ScanInput,
} from '@codetruss/analyzer-engine/security/engine'
import { zeroDependencyJsParser } from '@codetruss/analyzer-engine/security/js-parse/index'
import { mapSastFinding } from '@codetruss/analyzer-engine/security/finding-map'
import { CLI_SAST_RULE_IDS } from '@codetruss/analyzer-engine/security/local-profile'
import { sastLanguageForPath, type SastLanguage } from '@codetruss/analyzer-engine/security/lang'
import type { SastDiagnostics, SastResult } from '@codetruss/analyzer-engine/security/types'
import { loadGrammarParser } from './grammar-parser.js'

/**
 * The CLI's local security pass.
 *
 * Same engine, same rules, same taint solver as the hosted audit — behind a
 * zero-dependency parser instead of 6 MB of WASM grammars, and restricted to the
 * rule subset that has been differentially validated against the hosted parser
 * at zero false positives.
 *
 * Since 0.2.40 the pass has a SECOND parser: an opt-in grammar pack the user
 * installs explicitly (`codetruss grammars install python`). When present and
 * verified, Python is analyzed by the hosted runtime and grammar themselves, so
 * it runs the full rule pack rather than a subset — see {@link pythonRuleIds}.
 *
 * This is NOT one of the registry analyzers. Keeping it a separate pass is what
 * lets the receipt state the registry count truthfully while naming this pass
 * and its limits alongside them.
 */
export const LOCAL_SAST_PASS_ID = 'local-sast'

/** The grammar pack that extends this pass beyond the JS family. */
export const PYTHON_GRAMMAR_PACK = 'python'

/**
 * Declaration files (`*.d.ts`) carry no executable code, so no rule can fire in
 * them. Excluding them keeps the parser's coverage number honest instead of
 * reporting "degraded" for files where degradation is meaningless.
 */
function isDeclarationFile(path: string): boolean {
  return /\.d\.[cm]?ts$/i.test(path)
}

/** Production source in `languages`, in a deterministic order. */
function inputsForLanguages(index: RepoIndex, languages: ReadonlySet<SastLanguage>): ScanInput[] {
  const inputs: ScanInput[] = []
  for (const file of index.files) {
    if (!file.content) continue
    // Mirrors the hosted selection: security rules over vendored, generated or
    // test files are almost all false positives — tests exercise code, they are
    // not the attack surface.
    if (file.kind === 'vendored' || file.kind === 'generated' || file.kind === 'test') continue
    if (isDeclarationFile(file.path)) continue
    const language = sastLanguageForPath(file.path)
    if (!language || !languages.has(language)) continue
    inputs.push({ filePath: file.path, content: file.content })
  }
  // Deterministic order so findings and diagnostics are identical run to run.
  inputs.sort((a, b) => a.filePath.localeCompare(b.filePath))
  return inputs
}

/** Production JS-family source the local parser can analyze. */
export function localSastInputs(index: RepoIndex): ScanInput[] {
  return inputsForLanguages(index, zeroDependencyJsParser.languages)
}

/** Production Python source, analyzable only when the grammar pack is installed. */
export function localPythonInputs(index: RepoIndex): ScanInput[] {
  return inputsForLanguages(index, new Set<SastLanguage>(['python']))
}

/**
 * Which rules the Python scan may report: all of them.
 *
 * The JS-family subset ({@link CLI_SAST_RULE_IDS}) exists because the CLI parses
 * JavaScript with a hand-written parser, and only rules proven to agree with
 * tree-sitter on real repositories were allowed through. That reasoning does not
 * transfer here. A grammar pack IS the hosted parser and the hosted grammar, so
 * there is no divergence to guard against, and narrowing the pack would report
 * less than the same code would receive hosted — for no precision gain.
 */
const pythonRuleIds: ReadonlySet<string> | undefined = undefined

/** Why Python was or was not analyzed on this run. Rendered verbatim on receipts. */
export type PythonCoverageStatus = 'not-applicable' | 'absent' | 'verified' | 'failed'

/**
 * WHICH of the three unrelated things that all end in `failed` actually failed.
 *
 * `digest` — the pack on disk is not what this CLI published.
 * `runtime` — the pack verified and emscripten still would not start.
 * `scan`    — the pack verified, loaded, and then threw partway through.
 *
 * Kept apart because the receipt is a signed customer-facing document and the
 * three warrant different sentences. Collapsing them is how an out-of-memory
 * error on the user's laptop gets published as an accusation that their install
 * does not match the published digests — false, alarming, and unfalsifiable from
 * the reader's side.
 */
export type PythonPackFailureKind = 'digest' | 'runtime' | 'scan'

/**
 * Where this run's security evidence has a HOLE — files whose rules did not all
 * run, because a wall-clock ceiling cut the file short or the pass ended before
 * reaching it.
 *
 * Distinct from an analyzer's withheld set, and the difference is the whole
 * point. A withheld finding was FOUND and then dropped to respect an output cap,
 * so it can be handed to the delta as evidence of what a tree contained. A file
 * a clock cut was never analyzed: there is no finding to hand over, and the
 * tree's state there is unknown rather than clean. Only the paths can be
 * carried, so the delta knows which claims it has no basis to make.
 */
export interface SastCoverageGap {
  /** Files whose security evidence is incomplete in this tree. */
  paths: string[]
  /**
   * More files were cut than the diagnostics could name, so {@link paths} does
   * not identify them all. Reachable whenever the whole-pass ceiling fires: it
   * skips every remaining file, and only the first 50 are named. No SAST finding
   * can be attributed to a change on a run like that.
   */
  incomplete: boolean
}

/**
 * Read the gap out of a completed scan's diagnostics.
 *
 * The counts are authoritative and the path lists are bounded, so a run that cut
 * more files than it could name is reported as `incomplete` rather than
 * pretending the names it does have are the whole set.
 */
export function sastCoverageGap(diagnostics: SastDiagnostics): SastCoverageGap {
  const capped = diagnostics.timeCappedPaths ?? []
  const skipped = diagnostics.timeSkippedPaths ?? []
  return {
    paths: [...capped, ...skipped],
    incomplete:
      (diagnostics.timeCappedFiles ?? 0) > capped.length ||
      (diagnostics.timeSkippedFiles ?? 0) > skipped.length,
  }
}

export interface LocalSastResult {
  findings: AnalyzerFinding[]
  pass: AnalyzerPass
  /** Files this run could not fully analyze. Empty and complete on a clean run. */
  coverageGap: SastCoverageGap
}

const EMPTY_SCAN: SastResult = {
  findings: [],
  diagnostics: {
    inputFiles: 0,
    filesScanned: 0,
    filesSkipped: 0,
    degradedLanguages: [],
    truncatedFiles: 0,
    findingsTruncated: false,
  },
}

export async function runLocalSast(index: RepoIndex, env: NodeJS.ProcessEnv = process.env): Promise<LocalSastResult> {
  const jsInputs = localSastInputs(index)
  const pythonInputs = localPythonInputs(index)

  // The pack is only consulted when there is Python to analyze. A repository
  // with no Python gets no disclosure about Python, because there is nothing
  // there to have missed.
  let pythonStatus: PythonCoverageStatus = 'not-applicable'
  let pythonReason: string | undefined
  let pythonFailureKind: PythonPackFailureKind | undefined
  let pythonScan: SastResult = EMPTY_SCAN
  let pythonError: string | undefined

  if (pythonInputs.length > 0) {
    const load = await loadGrammarParser(PYTHON_GRAMMAR_PACK, env)
    if (load.status === 'absent') {
      pythonStatus = 'absent'
      pythonReason = 'the Python grammar pack is not installed'
    } else if (load.status === 'failed') {
      pythonStatus = 'failed'
      pythonReason = load.reason
      // The loader already knows whether this was the pack or the machine. Carry
      // that answer instead of re-deriving a worse one from the message.
      pythonFailureKind = load.kind
    } else {
      try {
        pythonScan = await scanFiles(pythonInputs, load.parser, { ruleIds: pythonRuleIds })
        pythonStatus = 'verified'
      } catch (error) {
        // A crash inside the grammar runtime is lost coverage, not a clean
        // Python result. Say so rather than let an empty finding list stand in.
        pythonStatus = 'failed'
        pythonReason = `grammar pack scan failed: ${error instanceof Error ? error.message : String(error)}`
        pythonFailureKind = 'scan'
        pythonError = pythonReason
        pythonScan = EMPTY_SCAN
      }
    }
  }

  let jsScan: SastResult = EMPTY_SCAN
  let jsError: string | undefined
  if (jsInputs.length > 0) {
    try {
      jsScan = await scanFiles(jsInputs, zeroDependencyJsParser, { ruleIds: CLI_SAST_RULE_IDS })
    } catch (error) {
      jsError = error instanceof Error ? error.message : String(error)
    }
  }

  const inputFiles = jsInputs.length + pythonInputs.length
  const merged = mergeSastResults([jsScan, pythonScan], inputFiles)
  const diagnostics = merged.diagnostics
  // A file a parser could not read is coverage lost, and the receipt has to say
  // so rather than let silence read as "nothing found there".
  const truncated =
    diagnostics.filesSkipped > 0 || diagnostics.truncatedFiles > 0 || diagnostics.findingsTruncated
  const findings = merged.findings.map((finding) => ({
    ...mapSastFinding(finding),
    analyzerId: LOCAL_SAST_PASS_ID,
  }))

  const details = [
    jsError ? `the JavaScript pass failed: ${jsError}` : undefined,
    pythonError,
    // Gated on the count it quotes: truncation now has more than one cause, and
    // "0 file(s) could not be parsed" on a run where the clock was the limit
    // would be a false sentence on a signed document.
    diagnostics.filesSkipped > 0
      ? `${diagnostics.filesSkipped} file(s) could not be parsed locally and were not analyzed`
      : undefined,
    // Named, never merely counted: a file the clock cut short is missing
    // evidence, and the receipt has to say which file rather than let a shorter
    // finding list read as a cleaner repository.
    timeCeilingDisclosure(diagnostics),
  ].filter((entry): entry is string => Boolean(entry))

  const error = jsError ?? pythonError

  return {
    findings,
    // Carried so the baseline/final delta can refuse to attribute anything
    // either tree could not see.
    coverageGap: sastCoverageGap(diagnostics),
    pass: {
      id: LOCAL_SAST_PASS_ID,
      result: {
        findings,
        complete: !truncated && !error && diagnostics.degradedLanguages.length === 0,
        truncated,
        ...(details.length ? { detail: details.join('; ') } : {}),
        metrics: {
          inputFiles: diagnostics.inputFiles,
          filesScanned: diagnostics.filesScanned,
          filesSkipped: diagnostics.filesSkipped,
          rules: CLI_SAST_RULE_IDS.size,
          // The receipt renders its Python disclosure from these, so what a
          // reader is told about coverage is derived from what actually ran on
          // this machine rather than from a sentence frozen at release time.
          pythonFiles: pythonInputs.length,
          pythonFilesScanned: pythonScan.diagnostics.filesScanned,
          pythonPackStatus: pythonStatus,
          ...(pythonReason ? { pythonPackReason: pythonReason } : {}),
          ...(pythonFailureKind ? { pythonPackFailureKind: pythonFailureKind } : {}),
        },
      },
      ...(error ? { error } : {}),
    },
  }
}
