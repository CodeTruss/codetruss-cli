import { chmod, mkdir, readFile, readdir, rename, unlink, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { suggestedFixLines } from './fix-suggestions.js'
import {
  loadSigningKey,
  normalizePublicKey,
  publicKeyFingerprint,
  sha256,
  signBytes,
  verifyBytes,
} from './signing.js'
import type { InferredScopeBasis, Receipt, SyncEnvelope, Verdict } from './types.js'

const SYNC_REDACTION = '[redacted unrelated path]'

function pathRelatedToChanges(path: string | undefined, changedPaths: string[]): boolean {
  if (!path) return false
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '')
  return changedPaths.some((changedPath) => (
    normalized === changedPath
    || normalized.startsWith(`${changedPath}/`)
    || changedPath.startsWith(`${normalized}/`)
  ))
}

function collectPotentialPaths(value: unknown, output: string[]): void {
  if (typeof value === 'string') {
    if (value.includes('/') || value.includes('\\') || /^[^\s]+\.[A-Za-z0-9]{1,12}$/.test(value)) output.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPotentialPaths(item, output)
    return
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) collectPotentialPaths(item, output)
  }
}

function pathVariants(path: string): string[] {
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '')
  const parts = normalized.split('/').filter(Boolean)
  return [...new Set([
    path,
    normalized,
    parts.length > 1 ? parts.slice(-2).join('/') : normalized,
  ].filter(Boolean))]
}

function redactKnownPaths(value: string, privatePaths: string[]): string {
  let redacted = value
  for (const path of privatePaths) redacted = redacted.replaceAll(path, SYNC_REDACTION)
  return redacted
}

export function newSessionId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1Z')
  return `${stamp}-${sha256(`${process.pid}:${Math.random()}:${now.getTime()}`).slice(0, 6)}`
}

/**
 * One immutable hook attempt owns one receipt path, even if the hook or CLI
 * process crashes after writing receipt files but before committing its result.
 */
export function hookSessionId(now: Date, attemptId: string): string {
  if (!/^[0-9a-f]{64}$/.test(attemptId)) throw new Error('hook receipt attempt id is invalid')
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1Z')
  return `${stamp}-hook-${attemptId}`
}

export function exitCode(verdict: Verdict): number {
  return verdict === 'PASS' ? 0 : verdict === 'REVIEW_REQUIRED' ? 1 : 2
}

function legacyScoreLines(receipt: Receipt): string[] {
  if ('analysisProfile' in receipt.analyzers || !receipt.analyzers.scores) return []
  return [
    `Final scores: health ${receipt.analyzers.scores.health}, debt ${receipt.analyzers.scores.debt}, architecture ${receipt.analyzers.scores.architecture}, security ${receipt.analyzers.scores.security}, docs ${receipt.analyzers.scores.docs}.`,
    ...(receipt.analyzers.baselineScores ? [
      `Baseline scores: health ${receipt.analyzers.baselineScores.health}, debt ${receipt.analyzers.baselineScores.debt}, architecture ${receipt.analyzers.baselineScores.architecture}, security ${receipt.analyzers.baselineScores.security}, docs ${receipt.analyzers.baselineScores.docs}.`,
    ] : []),
  ]
}

/**
 * What ran and what did not, named as detection rather than as a scoring
 * footnote — and dispatched on the receipt's own profile version.
 *
 * A receipt is evidence about one execution, so its rendering must describe the
 * pass set THAT execution had. A `local-registry-v1` receipt was signed when no
 * security pass ran locally at all; re-rendering it with v2's wording would
 * claim coverage that never happened, and would break its signature check.
 */
function analysisProfileLines(receipt: Receipt): string[] {
  const current = 'analysisProfile' in receipt.analyzers && receipt.analyzers.analysisProfile
  if (!current) {
    return [
      '## Analysis profile',
      '',
      'Legacy local receipt. Earlier CLI versions emitted numeric scores without hosted graph and SAST; those values are suppressed.',
      '',
      ...whatDidNotRunV1(receipt),
    ]
  }
  if (current.id === 'local-registry-v1') return omittedSastProfileLines(receipt, current.id)
  if (current.id === 'local-registry-v2') return thirteenAnalyzerProfileLines(receipt, current.id)
  if (current.id === 'local-registry-v3') return jsOnlySastProfileLines(receipt, current.id)

  const python = pythonCoverage(receipt)
  return [
    '## Analysis profile',
    '',
    `Profile: \`${current.id}\`.`,
    '',
    `The 15 deterministic registry analyzers ran locally on this machine, plus a local security pass: the shared SAST engine — the same rules and the same source-to-sink taint tracking as the hosted audit — over the ${python.analyzed ? 'JavaScript, TypeScript, TSX and Python' : 'JavaScript, TypeScript and TSX'} in this repository.`,
    '',
    '### What the local security pass checked',
    '',
    '- **SQL injection (CWE-89).** Untrusted input tracked from request sources through string building into query execution.',
    '- **Mass assignment (CWE-915).** A raw request body spread into a database write, and write helpers whose payload type accepts arbitrary keys.',
    '- **Un-awaited database writes, swallowed errors, coercion-prone `==` comparisons, and N+1 queries in loops** — the defect classes coding agents most often introduce.',
    ...(python.analyzed ? [
      `- **The complete rule pack over ${python.scanned} Python file(s).** The installed grammar pack is the same \`web-tree-sitter\` runtime and the same compiled grammar the hosted audit loads, so Python here was checked by the hosted machinery rather than an approximation of it — including the injection, traversal, SSRF and deserialization classes the JavaScript subset below omits.`,
    ] : []),
    '',
    '### What did not run',
    '',
    `- **The rest of the security rule pack${python.analyzed ? ', for JavaScript, TypeScript and TSX' : ''}.** Command injection, code injection, path traversal, SSRF, open redirect, XSS and insecure deserialization were **not** checked ${python.analyzed ? 'in those languages' : 'here'}. Those rules run in a hosted scan; absence of a finding in those classes means they were not analyzed, not that the code is clean.`,
    ...pythonDisclosureLines(python),
    '- **Hosted symbol graph.** No cross-file call or data-flow graph was built, so architecture and dead-code conclusions cover only what the local passes can see in isolation.',
    '- **Abstraction-shape analysis.** Single-implementation interfaces, options nobody overrides, and parameters never varied at any call site were not checked. They require the cross-file symbol graph, which does not run locally. This receipt says nothing either way about those shapes.',
    ...(receipt.llm ? [] : [
      '- **Optional LLM review.** No model read this diff. It is opt-in via `--llm` and is force-disabled under agent hooks, so a hook receipt is always deterministic evidence only.',
    ]),
    '- **Hosted Health scores.** Not calculated, reported as **N/A**. The scores are defined over the graph and the complete SAST pass; a number derived from this pass set would overstate what ran.',
    '',
    'Local security findings are reported for review and do not fail the verdict on their own.',
    '',
    'A PASS verdict means the passes listed above never ran and the passes that did run found nothing new. It is not a statement that this change is secure.',
    '',
    '[Run a hosted full audit](https://codetruss.com/dashboard/repos/new?source=cli-receipt).',
  ]
}

interface PythonCoverage {
  status: string
  /** Python files offered to the pass. Zero means the repository has none. */
  files: number
  scanned: number
  reason: string
  /** Which kind of failure, when the status is `failed`. See `local-sast.ts`. */
  failureKind: string
  analyzed: boolean
}

/**
 * What this run actually did about Python, read from the pass that did it.
 *
 * Derived from the signed JSON rather than from a constant, so the same receipt
 * always renders the same bytes while different runs can honestly say different
 * things. A receipt whose pass carries no Python metrics — the shape every
 * pre-0.2.40 client wrote — reads as "no Python", which is what those clients
 * meant, and the wording for that case is unchanged from v3.
 */
function pythonCoverage(receipt: Receipt): PythonCoverage {
  const metrics = receipt.analyzers.passes.find((pass) => pass.id === 'local-sast')?.result.metrics
  const status = typeof metrics?.pythonPackStatus === 'string' ? metrics.pythonPackStatus : 'not-applicable'
  const files = Number(metrics?.pythonFiles)
  const scanned = Number(metrics?.pythonFilesScanned)
  const reason = typeof metrics?.pythonPackReason === 'string' ? metrics.pythonPackReason : ''
  // A `failed` pass from a client that predates the taxonomy carries no kind.
  // `digest` is the safe default there only because it is what those clients
  // already rendered; nothing new is asserted about an old receipt.
  const failureKind = typeof metrics?.pythonPackFailureKind === 'string' ? metrics.pythonPackFailureKind : 'digest'
  return {
    status,
    files: Number.isFinite(files) ? files : 0,
    scanned: Number.isFinite(scanned) ? scanned : 0,
    reason,
    failureKind,
    analyzed: status === 'verified' && Number.isFinite(scanned) && scanned > 0,
  }
}

/**
 * The non-JavaScript-language paragraph, in the states it can be in.
 *
 * "Skipped" and "skipped because the bytes did not verify" are different facts
 * and a reader has to be able to tell them apart: the first is a choice they can
 * reverse with one command, the second means something on their machine is not
 * what this CLI published. The three FAILURE kinds are different facts for the
 * same reason — only one of them is about the pack at all, and a receipt that
 * blames a user's install for their machine's out-of-memory error has published
 * an accusation it cannot support.
 *
 * The closing sentence in every failure branch is deliberately the provable one.
 * "Nothing was analyzed with unverified bytes" is true of this loader — it holds
 * one buffer per artifact and executes that buffer — but it is an assertion
 * about the CLI's internals that a receipt's reader has no way to check, and it
 * makes a claim wider than this pass can speak to. "No findings from this pack
 * were reported" says less and is verifiable against the receipt in hand.
 */
function pythonDisclosureLines(python: PythonCoverage): string[] {
  const others = 'Go, Java, C#, PHP, Ruby and Rust'
  if (python.status === 'verified' && python.analyzed) {
    return [
      `- **Non-JavaScript languages other than Python.** ${others} in this repository received secret scanning and the other registry passes, but no security rule or taint analysis.`,
    ]
  }
  if (python.status === 'absent') {
    return [
      `- **Python.** ${python.files} Python file(s) here received secret scanning and the other registry passes, but no security rule or taint analysis: the optional Python grammar pack is not installed. Install it with \`codetruss grammars install python\` to analyze them locally, or run a hosted scan.`,
      `- **Other non-JavaScript languages.** ${others} in this repository were likewise not covered by any security rule or taint analysis.`,
    ]
  }
  if (python.status === 'failed') {
    return [
      `- **Python.** ${python.files} Python file(s) were **not** analyzed. ${pythonFailureSentence(python)} No findings from this pack were reported.`,
      `- **Other non-JavaScript languages.** ${others} in this repository received secret scanning and the other registry passes, but no security rule or taint analysis.`,
    ]
  }
  return [
    `- **Non-JavaScript languages.** The local pass covered JavaScript, TypeScript and TSX. Python, ${others} in this repository received secret scanning and the other registry passes, but no security rule or taint analysis.`,
  ]
}

/** The one sentence that differs between the three ways a pack run can fail. */
function pythonFailureSentence(python: PythonCoverage): string {
  if (python.failureKind === 'runtime') {
    // The digests PASSED here. Saying so is the point: the user's install is
    // fine and the problem is this machine or this Node build.
    return `The installed Python grammar pack matched the digests compiled into this CLI, but its runtime could not start on this machine, so no Python was parsed: ${python.reason}.`
  }
  if (python.failureKind === 'scan') {
    return `The installed Python grammar pack verified and loaded, but the scan failed partway through and its partial results were discarded rather than reported as a complete Python result: ${python.reason}.`
  }
  return `The installed Python grammar pack did not verify against what this CLI published, so it was not loaded: ${python.reason}. Reinstall it with \`codetruss grammars install python\`.`
}

/**
 * The profile block exactly as CLI 0.2.39 wrote it, when the local pass could
 * only ever reach the JS family. Frozen so those receipts still reproduce
 * byte-for-byte.
 */
function jsOnlySastProfileLines(receipt: Receipt, profileId: string): string[] {
  return [
    '## Analysis profile',
    '',
    `Profile: \`${profileId}\`.`,
    '',
    'The 15 deterministic registry analyzers ran locally on this machine, plus a local security pass: the shared SAST engine — the same rules and the same source-to-sink taint tracking as the hosted audit — over the JavaScript, TypeScript and TSX in this repository.',
    '',
    '### What the local security pass checked',
    '',
    '- **SQL injection (CWE-89).** Untrusted input tracked from request sources through string building into query execution.',
    '- **Mass assignment (CWE-915).** A raw request body spread into a database write, and write helpers whose payload type accepts arbitrary keys.',
    '- **Un-awaited database writes, swallowed errors, coercion-prone `==` comparisons, and N+1 queries in loops** — the defect classes coding agents most often introduce.',
    '',
    '### What did not run',
    '',
    '- **The rest of the security rule pack.** Command injection, code injection, path traversal, SSRF, open redirect, XSS and insecure deserialization were **not** checked here. Those rules run in a hosted scan; absence of a finding in those classes means they were not analyzed, not that the code is clean.',
    '- **Non-JavaScript languages.** The local pass covers JavaScript, TypeScript and TSX only. Python, Go, Java, C#, PHP, Ruby and Rust in this repository received secret scanning and the other registry passes, but no security rule or taint analysis.',
    '- **Hosted symbol graph.** No cross-file call or data-flow graph was built, so architecture and dead-code conclusions cover only what the local passes can see in isolation.',
    '- **Abstraction-shape analysis.** Single-implementation interfaces, options nobody overrides, and parameters never varied at any call site were not checked. They require the cross-file symbol graph, which does not run locally. This receipt says nothing either way about those shapes.',
    ...(receipt.llm ? [] : [
      '- **Optional LLM review.** No model read this diff. It is opt-in via `--llm` and is force-disabled under agent hooks, so a hook receipt is always deterministic evidence only.',
    ]),
    '- **Hosted Health scores.** Not calculated, reported as **N/A**. The scores are defined over the graph and the complete SAST pass; a number derived from this pass set would overstate what ran.',
    '',
    'Local security findings are reported for review and do not fail the verdict on their own.',
    '',
    'A PASS verdict means the passes listed above never ran and the passes that did run found nothing new. It is not a statement that this change is secure.',
    '',
    '[Run a hosted full audit](https://codetruss.com/dashboard/repos/new?source=cli-receipt).',
  ]
}

/**
 * The profile block exactly as CLI 0.2.35–0.2.38 wrote it, when the registry
 * held thirteen analyzers and abstraction shape was not disclosed. Frozen so
 * those receipts still reproduce byte-for-byte.
 */
function thirteenAnalyzerProfileLines(receipt: Receipt, profileId: string): string[] {
  return [
    '## Analysis profile',
    '',
    `Profile: \`${profileId}\`.`,
    '',
    'The 13 deterministic registry analyzers ran locally on this machine, plus a local security pass: the shared SAST engine — the same rules and the same source-to-sink taint tracking as the hosted audit — over the JavaScript, TypeScript and TSX in this repository.',
    '',
    '### What the local security pass checked',
    '',
    '- **SQL injection (CWE-89).** Untrusted input tracked from request sources through string building into query execution.',
    '- **Mass assignment (CWE-915).** A raw request body spread into a database write, and write helpers whose payload type accepts arbitrary keys.',
    '- **Un-awaited database writes, swallowed errors, coercion-prone `==` comparisons, and N+1 queries in loops** — the defect classes coding agents most often introduce.',
    '',
    '### What did not run',
    '',
    '- **The rest of the security rule pack.** Command injection, code injection, path traversal, SSRF, open redirect, XSS and insecure deserialization were **not** checked here. Those rules run in a hosted scan; absence of a finding in those classes means they were not analyzed, not that the code is clean.',
    '- **Non-JavaScript languages.** The local pass covers JavaScript, TypeScript and TSX only. Python, Go, Java, C#, PHP, Ruby and Rust in this repository received secret scanning and the other registry passes, but no security rule or taint analysis.',
    '- **Hosted symbol graph.** No cross-file call or data-flow graph was built, so architecture and dead-code conclusions cover only what the local passes can see in isolation.',
    ...(receipt.llm ? [] : [
      '- **Optional LLM review.** No model read this diff. It is opt-in via `--llm` and is force-disabled under agent hooks, so a hook receipt is always deterministic evidence only.',
    ]),
    '- **Hosted Health scores.** Not calculated, reported as **N/A**. The scores are defined over the graph and the complete SAST pass; a number derived from this pass set would overstate what ran.',
    '',
    'Local security findings are reported for review and do not fail the verdict on their own.',
    '',
    'A PASS verdict means the passes listed above never ran and the passes that did run found nothing new. It is not a statement that this change is secure.',
    '',
    '[Run a hosted full audit](https://codetruss.com/dashboard/repos/new?source=cli-receipt).',
  ]
}

/**
 * The profile block exactly as CLI 0.2.29–0.2.34 wrote it, when the SAST pass
 * was omitted from local analysis entirely. Frozen so those receipts still
 * reproduce byte-for-byte.
 */
function omittedSastProfileLines(receipt: Receipt, profileId: string): string[] {
  return [
    '## Analysis profile',
    '',
    `Profile: \`${profileId}\`.`,
    '',
    'The 13 deterministic registry analyzers ran locally on this machine.',
    '',
    ...whatDidNotRunV1(receipt),
  ]
}

function whatDidNotRunV1(receipt: Receipt): string[] {
  return [
    '### What did not run',
    '',
    '- **Security static analysis (SAST).** No injection or taint analysis was performed. SQL injection, command injection, code injection, path traversal, SSRF, open redirect, XSS and insecure deserialization were never checked, so this receipt says nothing either way about those classes.',
    '- **Hosted symbol graph.** No cross-file call or data-flow graph was built, so architecture and dead-code conclusions cover only what the local passes can see in isolation.',
    ...(receipt.llm ? [] : [
      '- **Optional LLM review.** No model read this diff. It is opt-in via `--llm` and is force-disabled under agent hooks, so a hook receipt is always deterministic evidence only.',
    ]),
    '- **Hosted Health scores.** Not calculated, reported as **N/A**. The scores are defined over the graph and SAST passes; a number derived from this pass set would overstate what ran.',
    '',
    'A PASS verdict means the passes listed above never ran and the passes that did run found nothing new. It is not a statement that this change is secure.',
    '',
    '[Run a hosted full audit](https://codetruss.com/dashboard/repos/new?source=cli-receipt).',
  ]
}

/**
 * The profile block exactly as CLI 0.2.28 and earlier wrote it. Kept verbatim
 * so `codetruss verify` still reproduces Markdown that was signed before the
 * disclosure was reworded; the signed JSON is unchanged, only its rendering.
 */
function priorProfileLines(receipt: Receipt): string[] {
  const current = 'analysisProfile' in receipt.analyzers && receipt.analyzers.analysisProfile
  return [
    '## Analysis profile',
    '',
    ...(current ? [
      `Profile: \`${current.id}\`.`,
      '',
      'The 13 deterministic registry analyzers ran locally. Hosted graph and SAST passes were omitted.',
    ] : [
      'Legacy local receipt. Earlier CLI versions emitted numeric scores without hosted graph and SAST; those values are suppressed.',
    ]),
    '',
    'Hosted Health scores: **N/A**. Local receipts do not calculate hosted scores without the graph and SAST passes.',
    '',
    '[Run a hosted full audit](https://codetruss.com/dashboard/repos/new?source=cli-receipt).',
  ]
}

const INFERRED_BASIS_LABELS: Record<InferredScopeBasis, string> = {
  'task-reference': 'named in the task',
  'working-set': 'working set for this turn',
  'sibling-test': 'test beside changed source',
}

function scopeCell(file: Receipt['files'][number]): string {
  return file.classification === 'inferred' ? 'allowed (inferred)' : file.classification
}

/**
 * Inferred scope, disclosed as what it is.
 *
 * A reviewer must never have to wonder whether a path was in scope because the
 * repository approved it or because CodeTruss worked it out. This block names
 * the weaker allowances, what each was read from, and the approved roots they
 * sit beside — and it renders only when a turn actually used one, so receipts
 * signed before inference existed still reproduce byte for byte.
 */
function inferredScopeLines(receipt: Receipt): string[] {
  const inferred = receipt.scope.inferred ?? []
  if (inferred.length === 0) return []
  const covered = receipt.files.filter((file) => file.classification === 'inferred').length
  return [
    '',
    `## Inferred scope (${inferred.length})`,
    '',
    `${covered} changed file(s) matched no approved allow root. CodeTruss read the allowances below from this turn's own task text and changed files, and applied them to this turn only. They were not written to \`.codetruss.yml\` and do not carry forward.`,
    '',
    '| Inferred root | Read from | Evidence |',
    '|---|---|---|',
    ...inferred.map((root) => `| \`${root.root.replaceAll('|', '\\|')}\` | ${INFERRED_BASIS_LABELS[root.basis]} | ${root.evidence.map((item) => `\`${item.replaceAll('|', '\\|')}\``).join(', ')} |`),
    '',
    receipt.scope.allow.length
      ? `Approved allow roots: ${receipt.scope.allow.map((glob) => `\`${glob}\``).join(', ')}.`
      : 'This repository has no approved allow roots, so its scope for this turn was inferred entirely.',
    '',
    'Denied paths, sensitive surfaces, and dependency manifests are never inferable. Each allowance above is a function of the task and changed-file list in this receipt, so the same result can be recomputed from these bytes.',
  ]
}

/**
 * The comment-shape measurement, rendered from pass metrics rather than from
 * findings.
 *
 * A healthy repository produces no comment finding at all, and a repo-level
 * "nothing restates the code" finding could never reach a hook receipt anyway:
 * it carries the same fingerprint in the baseline and the final tree, so the
 * delta files it under recurring. The positive signal has to come from the
 * numbers the pass already reports.
 *
 * Emits nothing when the pass carries no metrics, so every receipt signed
 * before this analyzer existed still renders to its original bytes.
 *
 * The counted thing is COMMENTS, and the reported thing is FILES OVER THE
 * THRESHOLD. Stating only the second as though it were the first would be the
 * one false sentence on an honest receipt: a file holding two restating
 * comments is under the reporting threshold, but "0 files carry comments that
 * restate the code" is not true of it.
 */
function commentSignalLines(receipt: Receipt): string[] {
  const metrics = receipt.analyzers.passes.find((pass) => pass.id === 'comment-slop')?.result.metrics
  if (!metrics) return []
  const files = Number(metrics.eligibleFiles)
  const median = Number(metrics.commentRatioMedian)
  const restating = Number(metrics.redundantComments)
  const narrating = Number(metrics.narrationComments)
  const reported = Number(metrics.redundantCommentFiles) + Number(metrics.narrationCommentFiles)
  if (![files, median, restating, narrating, reported].every(Number.isFinite) || files <= 0) return []
  return [
    '',
    '## Comment signal',
    '',
    `This repository comments at a median of ${median} lines per code line. Across the ${files} file(s) measured, `
    + `${restating} comment(s) restate the code beneath them and ${narrating} narrate an edit rather than describe `
    + 'behaviour.',
    '',
    restating + narrating === 0
      ? 'Nothing in this repository matched either shape.'
      : reported === 0
        ? 'No file carries enough of either shape to be reported, so neither appears in the findings table.'
        : `${reported} file(s) carry enough of either shape to be reported. The findings table above lists only what `
          + 'this session introduced or worsened; the counts here cover the whole repository.',
  ]
}

function tableCell(value: string): string {
  return value.replaceAll('|', '\\|')
}

function findingLocation(finding: Receipt['analyzers']['findings'][number]): string {
  return finding.filePath ? `\`${finding.filePath}${finding.line ? `:${finding.line}` : ''}\`` : 'repository'
}

/** At most this many dismissals are tabulated; the signed JSON always holds them all. */
const SUPPRESSION_ROW_LIMIT = 100
/** At most this many reason-less marker locations are named inline. */
const REJECTED_MARKER_LIMIT = 20

/**
 * What a `codetruss-ignore` comment did to this analysis.
 *
 * A dismissed finding is REPORTED as dismissed, never omitted. The product's
 * whole claim is that the receipt states what was and was not flagged; a receipt
 * that silently dropped a finding because a comment in the repository told it to
 * would make "nothing was found" reachable by editing a comment, and the
 * signature would then be attesting to a sentence the evidence does not support.
 * So the finding, its location, and the exact reason its author gave all survive
 * into the signed bytes, and the reader decides whether the reason is good.
 *
 * Markers that gave no reason are named too. They dismiss nothing — a reason is
 * required precisely because the reason is the evidence — and a developer who
 * wrote one has to be able to find out why nothing happened.
 *
 * Emits nothing when a repository dismissed nothing, so every receipt signed
 * before suppression existed still renders, and verifies, byte for byte.
 */
function suppressionLines(receipt: Receipt): string[] {
  const suppressed = receipt.analyzers.suppressed ?? []
  const rejected = receipt.analyzers.rejectedSuppressions ?? []
  if (suppressed.length === 0 && rejected.length === 0) return []
  const rows = suppressed.slice(0, SUPPRESSION_ROW_LIMIT)
  const namedMarkers = rejected.slice(0, REJECTED_MARKER_LIMIT)
  return [
    '',
    `## Suppressed findings (${suppressed.length})`,
    ...(suppressed.length ? [
      '',
      'The analyzers above produced these findings, and a `codetruss-ignore: <reason>` comment in the source dismissed them. They did not affect the verdict. This list covers the whole repository, not only the changed files.',
      '',
      '| Severity | Analyzer | Location | Finding | Reason given |',
      '|---|---|---|---|---|',
      ...rows.map((finding) => `| ${finding.severity} | ${finding.analyzerId ?? 'unknown'} | ${findingLocation(finding)} | ${tableCell(finding.title)} | ${tableCell(finding.suppression?.reason ?? '')} |`),
      ...(suppressed.length > rows.length
        ? ['', `${suppressed.length - rows.length} further dismissed finding(s) are recorded in the signed JSON and not tabulated here.`]
        : []),
    ] : [
      '',
      'Nothing was dismissed in this repository.',
    ]),
    ...(rejected.length ? [
      '',
      `${rejected.length} \`codetruss-ignore\` marker(s) gave no reason and therefore dismissed nothing: ${namedMarkers.map((site) => `\`${site}\``).join(', ')}${rejected.length > namedMarkers.length ? `, and ${rejected.length - namedMarkers.length} more` : ''}. A dismissal is accepted only as \`codetruss-ignore: <reason>\`, because the reason is the evidence. Those findings are still reported above.`,
    ] : []),
  ]
}

/** Which historical rendering of the analysis block to reproduce. */
type ReceiptMarkdownVariant = 'current' | 'legacy-scores' | 'prior-profile'

function analysisLines(receipt: Receipt, variant: ReceiptMarkdownVariant): string[] {
  if (variant === 'legacy-scores') return legacyScoreLines(receipt)
  if (variant === 'prior-profile') return priorProfileLines(receipt)
  return analysisProfileLines(receipt)
}

function renderMarkdownInternal(receipt: Receipt, variant: ReceiptMarkdownVariant): string {
  const lines = [
    `# CodeTruss receipt — ${receipt.verdict}`,
    '',
    `- **Session:** \`${receipt.sessionId}\``,
    `- **Task:** ${receipt.task.replaceAll('\n', ' ')}`,
    `- **Repository:** \`${receipt.repoRoot}\``,
    `- **Starting commit:** \`${receipt.startCommit || '(unborn)'}\``,
    ...(receipt.git ? [`- **Evidence trees:** \`${receipt.git.baselineTree}\` → \`${receipt.git.finalTree}\``] : []),
    ...(receipt.policy ? [`- **Policy SHA-256:** \`${receipt.policy.sha256}\``] : []),
    `- **Mode:** ${receipt.mode}`,
    '',
    `## Verdict: ${receipt.verdict}`,
    '',
    ...receipt.reasons.map((reason) => `- ${reason}`),
    '',
    `Diff evidence: ${receipt.diff.bytes}/${receipt.diff.totalBytes ?? receipt.diff.bytes} bytes captured${receipt.diff.truncated ? ' (truncated; PASS prohibited)' : ' (complete)'}, SHA-256 \`${receipt.diff.sha256.slice(0, 16)}…\`.`,
    '',
    `## Changed files (${receipt.files.length})`,
    '',
    '| Path | Change | Scope | Sensitive | Lines |',
    '|---|---|---|---|---:|',
    ...receipt.files.map((file) => `| \`${file.path.replaceAll('|', '\\|')}\` | ${file.change} | ${scopeCell(file)} | ${file.sensitive ?? (file.dependency ? 'dependency' : '—')} | +${file.additions}/−${file.deletions} |`),
    ...inferredScopeLines(receipt),
    '',
    `## Introduced or worsened analyzer findings (${receipt.analyzers.findings.length})`,
    '',
    '| Severity | Analyzer | Location | Finding |',
    '|---|---|---|---|',
    ...receipt.analyzers.findings.slice(0, 100).map((finding) => `| ${finding.severity} | ${finding.analyzerId ?? 'unknown'} | ${findingLocation(finding)} | ${tableCell(finding.title)} |`),
    ...suppressionLines(receipt),
    '',
    // Emits nothing when no finding carries a fix, so every receipt signed
    // before suggestions existed still renders to its original bytes.
    ...suggestedFixLines(receipt.analyzers.findings),
    ...commentSignalLines(receipt),
    ...analysisLines(receipt, variant),
    ...(receipt.analyzers.delta ? [
      `Finding delta: ${receipt.analyzers.delta.introduced} introduced, ${receipt.analyzers.delta.worsened} worsened, ${receipt.analyzers.delta.recurring} recurring, ${receipt.analyzers.delta.resolved} resolved.`,
    ] : []),
    '',
    '## Verification',
    '',
    ...(receipt.verifications.length ? receipt.verifications.map((item) => `- \`${item.command}\` — exit ${item.exitCode} in ${item.durationMs}ms${item.truncated ? ' (output truncated)' : ''}`) : ['- No verification commands configured.']),
  ]
  if (receipt.llm) {
    const coverage = receipt.llm.diffCoverage
    lines.push(
      '',
      '## Optional LLM review',
      '',
      coverage
        ? `Provider: ${receipt.llm.provider}. Sent ${receipt.llm.transmittedBytes} bytes directly to that provider. Reviewed ${coverage.reviewedBytes}/${coverage.totalBytes} diff bytes${coverage.truncated ? ' (truncated; PASS prohibited)' : ' (complete)'}.`
        : `Provider: ${receipt.llm.provider}. Sent ${receipt.llm.transmittedBytes} bytes directly to that provider.`,
      '',
      receipt.llm.summary,
      ...receipt.llm.findings.map((item) => `- ${item}`),
    )
  }
  lines.push('', '## Coverage and privacy', '', ...receipt.coverageNotes.map((note) => `- ${note}`), '', '_The signature proves these receipt bytes have not changed since signing. It does not prove trusted execution or that every analysis conclusion is correct._', '')
  return lines.join('\n')
}

/** Render the current honest local profile, including when displaying a legacy receipt. */
export function renderMarkdown(receipt: Receipt): string {
  return renderMarkdownInternal(receipt, 'current')
}

/** Byte-compatible renderer used only to verify Markdown written by older receipt-v1 clients. */
export function renderLegacyMarkdown(receipt: Receipt): string {
  return renderMarkdownInternal(receipt, 'legacy-scores')
}

/** Byte-compatible renderer for profile receipts signed before the disclosure was reworded. */
export function renderPriorProfileMarkdown(receipt: Receipt): string {
  return renderMarkdownInternal(receipt, 'prior-profile')
}

async function writePrivateAtomic(path: string, value: string | Buffer): Promise<void> {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  try {
    await writeFile(temporary, value, { mode: 0o600, flag: 'wx' })
    await rename(temporary, path)
    await chmod(path, 0o600)
  } catch (error) {
    try { await unlink(temporary) } catch {}
    throw error
  }
}

export async function writeReceipt(dir: string, receipt: Receipt, patch: string | Buffer): Promise<{ json: string; markdown: string; signature: string }> {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  await chmod(dir, 0o700)
  const patchName = `${receipt.sessionId}.patch`
  const patchPath = join(dir, patchName)
  await writePrivateAtomic(patchPath, patch)
  receipt.evidence.patchFile = patchName
  receipt.evidence.patchSha256 = sha256(patch)
  const markdown = renderMarkdown(receipt)
  receipt.evidence.markdownSha256 = sha256(markdown)
  const key = await loadSigningKey(true)
  receipt.evidence.signatureFile = `${receipt.sessionId}.sig`
  receipt.evidence.publicKey = key.publicKey
  receipt.evidence.keyFingerprint = key.fingerprint
  const jsonText = `${JSON.stringify(receipt, null, 2)}\n`
  const signature = signBytes(jsonText, key.privateKey)
  const jsonPath = join(dir, `${receipt.sessionId}.json`)
  const markdownPath = join(dir, `${receipt.sessionId}.md`)
  const signaturePath = join(dir, `${receipt.sessionId}.sig`)
  await writePrivateAtomic(jsonPath, jsonText)
  await writePrivateAtomic(markdownPath, markdown)
  await writePrivateAtomic(signaturePath, `${signature}\n`)
  return { json: jsonPath, markdown: markdownPath, signature: signaturePath }
}

export async function receiptIds(dir: string): Promise<string[]> {
  try { return (await readdir(dir)).filter((name) => name.endsWith('.json')).map((name) => basename(name, '.json')).sort().reverse() } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error }
}

export async function resolveReceipt(dir: string, id = 'latest'): Promise<{ receipt: Receipt; jsonPath: string }> {
  const ids = await receiptIds(dir)
  const resolved = id === 'latest' ? ids[0] : id
  if (!resolved || !ids.includes(resolved)) throw new Error(`receipt ${id} not found`)
  const jsonPath = join(dir, `${resolved}.json`)
  return { receipt: JSON.parse(await readFile(jsonPath, 'utf8')) as Receipt, jsonPath }
}

export async function verifyReceipt(dir: string, id = 'latest', pinnedPublicKey?: string | string[]): Promise<Receipt> {
  const { receipt, jsonPath } = await resolveReceipt(dir, id)
  if (receipt.git && ![receipt.git.baselineTree, receipt.git.finalTree].every((oid) => /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(oid))) {
    throw new Error('receipt evidence tree object id is invalid')
  }
  if (receipt.policy && !/^[0-9a-f]{64}$/.test(receipt.policy.sha256)) {
    throw new Error('receipt policy SHA-256 is invalid')
  }
  if (!receipt.evidence.publicKey || !receipt.evidence.signatureFile) throw new Error('receipt is unsigned')
  // A repository may trust several signers (one per developer). The receipt is
  // valid when its embedded key is one of them, and the signature is then
  // checked against that exact key — so a teammate's receipt verifies without
  // anyone sharing a private key.
  const pins = Array.isArray(pinnedPublicKey) ? pinnedPublicKey : pinnedPublicKey ? [pinnedPublicKey] : []
  const trustedPublicKeys = pins.length > 0
    ? pins.map((pin) => normalizePublicKey(pin))
    : [(await loadSigningKey()).publicKey]
  const embeddedPublicKey = normalizePublicKey(receipt.evidence.publicKey)
  const embeddedFingerprint = publicKeyFingerprint(embeddedPublicKey)
  const trustedFingerprints = trustedPublicKeys.map((key) => publicKeyFingerprint(key))
  if (receipt.evidence.keyFingerprint !== embeddedFingerprint) throw new Error('receipt signing fingerprint does not match its public key')
  if (!trustedFingerprints.includes(embeddedFingerprint)) {
    throw new Error(`receipt signer ${embeddedFingerprint} does not match trusted key ${trustedFingerprints.join(', ')}`)
  }
  const trustedPublicKey = trustedPublicKeys[trustedFingerprints.indexOf(embeddedFingerprint)]
  const jsonBytes = await readFile(jsonPath)
  const signature = (await readFile(join(dir, receipt.evidence.signatureFile), 'utf8')).trim()
  if (!verifyBytes(jsonBytes, trustedPublicKey, signature)) throw new Error('receipt signature does not match')
  const markdown = await readFile(join(dir, `${receipt.sessionId}.md`), 'utf8')
  // Every rendering this exact signed JSON could legitimately have produced.
  // Rewording a disclosure must not invalidate receipts already on disk, so
  // each superseded wording stays reproducible for verification only.
  const profile = 'analysisProfile' in receipt.analyzers ? receipt.analyzers.analysisProfile : null
  const accepted = [
    renderMarkdown(receipt),
    // Superseded wordings are accepted only for the profile version that could
    // have produced them. A `local-registry-v2` receipt was never written by a
    // CLI that omitted SAST, so its Markdown must not be allowed to say so.
    ...(!profile ? [renderLegacyMarkdown(receipt)] : []),
    ...(profile?.id === 'local-registry-v1' ? [renderPriorProfileMarkdown(receipt)] : []),
  ]
  if (!accepted.includes(markdown)) throw new Error('Markdown receipt does not match the signed JSON')
  if (sha256(markdown) !== receipt.evidence.markdownSha256) throw new Error('Markdown receipt hash does not match')
  if (receipt.evidence.patchFile) {
    const patch = await readFile(join(dir, receipt.evidence.patchFile))
    if (sha256(patch) !== receipt.evidence.patchSha256) throw new Error('captured patch hash does not match')
    if (sha256(patch) !== receipt.diff.sha256) throw new Error('captured patch does not match the signed diff hash')
    if (patch.length !== receipt.diff.bytes) throw new Error('captured patch byte count does not match the signed receipt')
    const totalBytes = receipt.diff.totalBytes ?? receipt.diff.bytes
    if (totalBytes < receipt.diff.bytes || receipt.diff.truncated !== (totalBytes > receipt.diff.bytes)) {
      throw new Error('captured patch truncation metadata is inconsistent')
    }
  }
  return receipt
}

/** Create a signed, privacy-minimized copy for an explicit hosted sync. */
export async function createSyncEnvelope(receipt: Receipt): Promise<SyncEnvelope> {
  const key = await loadSigningKey()
  const synced = structuredClone(receipt)
  const changedPaths = [...new Set(receipt.files.flatMap((file) => [file.path, file.oldPath])
    .filter((path): path is string => Boolean(path))
    .map((path) => path.replaceAll('\\', '/').replace(/^\.\//, '')))]
  const possiblePrivatePaths = [
    receipt.repoRoot,
    ...receipt.startDirtyFiles.filter((path) => !pathRelatedToChanges(path, changedPaths)),
    ...receipt.analyzers.findings
      .map((finding) => finding.filePath)
      .filter((path): path is string => Boolean(path) && !pathRelatedToChanges(path, changedPaths)),
    ...receipt.analyzers.passes.flatMap((pass) => pass.result.findings
      .map((finding) => finding.filePath)
      .filter((path): path is string => Boolean(path) && !pathRelatedToChanges(path, changedPaths))),
  ]
  for (const finding of receipt.analyzers.findings) collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  for (const finding of receipt.analyzers.suppressed ?? []) {
    if (finding.filePath && !pathRelatedToChanges(finding.filePath, changedPaths)) possiblePrivatePaths.push(finding.filePath)
    collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  }
  for (const pass of receipt.analyzers.passes) {
    for (const finding of pass.result.findings) collectPotentialPaths(finding.metadata, possiblePrivatePaths)
  }
  const privatePaths = [...new Set(possiblePrivatePaths
    .filter((path) => !pathRelatedToChanges(path, changedPaths))
    .flatMap(pathVariants))]
    .sort((left, right) => right.length - left.length)

  synced.repoRoot = basename(receipt.repoRoot)
  synced.startDirtyFiles = synced.startDirtyFiles.filter((path) => pathRelatedToChanges(path, changedPaths))
  if (synced.agent) {
    synced.agent.command = synced.agent.command.length ? [basename(synced.agent.command[0])] : []
    delete synced.agent.startError
  }
  // Analyzer passes contain a second, whole-repository copy of every finding.
  // Sync only pass completion status and the separately filtered changed-file findings.
  synced.analyzers.passes = synced.analyzers.passes.map((pass) => {
    const result: Receipt['analyzers']['passes'][number]['result'] = {
      findings: [],
      complete: pass.result.complete,
    }
    if (pass.result.truncated !== undefined) result.truncated = pass.result.truncated
    return { id: pass.id, result }
  })
  const sanitizeFindings = (findings: Receipt['analyzers']['findings']): Receipt['analyzers']['findings'] => findings
    .filter((finding) => !finding.filePath || pathRelatedToChanges(finding.filePath, changedPaths))
    .map((finding) => {
      const sanitized = {
        ...finding,
        title: redactKnownPaths(finding.title, privatePaths),
        description: redactKnownPaths(finding.description, privatePaths),
      }
      if (finding.suggestion !== undefined) sanitized.suggestion = redactKnownPaths(finding.suggestion, privatePaths)
      // A dismissal reason is free text a developer wrote; it gets the same
      // path redaction as every other prose field on the way out.
      if (finding.suppression) {
        sanitized.suppression = { ...finding.suppression, reason: redactKnownPaths(finding.suppression.reason, privatePaths) }
      }
      delete sanitized.metadata
      // A suggested fix quotes real source lines and local paths. It stays on
      // the machine that produced it — the hosted copy never needs it.
      delete sanitized.fix
      return sanitized
    })
  synced.analyzers.findings = sanitizeFindings(synced.analyzers.findings)
  if (synced.analyzers.suppressed) {
    const suppressed = sanitizeFindings(synced.analyzers.suppressed)
    if (suppressed.length) synced.analyzers.suppressed = suppressed
    else delete synced.analyzers.suppressed
  }
  if (synced.analyzers.rejectedSuppressions) {
    // `path:line`, so the path is everything before the final colon.
    const sites = synced.analyzers.rejectedSuppressions
      .filter((site) => pathRelatedToChanges(site.slice(0, site.lastIndexOf(':')), changedPaths))
    if (sites.length) synced.analyzers.rejectedSuppressions = sites
    else delete synced.analyzers.rejectedSuppressions
  }
  synced.verifications = synced.verifications.map((item) => ({ ...item, command: '[redacted for sync]', output: '' }))
  synced.evidence = {
    patchSha256: receipt.evidence.patchSha256,
    publicKey: key.publicKey,
    keyFingerprint: key.fingerprint,
  }
  synced.coverageNotes = [
    ...synced.coverageNotes,
    'Hosted sync copy redacted the absolute repository path, unrelated dirty paths, agent arguments/start error, verification commands/output, duplicate whole-repository analyzer finding bodies, unrelated analyzer paths/metadata, suggested-fix bodies, and local evidence filenames.',
  ]
  const signedReceipt = `${JSON.stringify(synced, null, 2)}\n`
  return { signedReceipt, signature: signBytes(signedReceipt, key.privateKey) }
}
