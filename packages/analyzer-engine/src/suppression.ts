import type { AnalyzerFinding, FindingSuppression, RepoIndex } from './types'

/**
 * Inline finding suppression: `codetruss-ignore: <reason>`.
 *
 * A developer who has judged a finding wrong needs a way to say so in the one
 * place the judgement belongs — beside the code it is about. The marker mirrors
 * `gitleaks:allow` in placement and differs from it in two deliberate ways.
 *
 * FIRST, a reason is mandatory. The marker's entire output is a line of evidence
 * on a signed receipt, and "someone decided this was fine" is not evidence. A
 * bare `codetruss-ignore` therefore suppresses nothing and is recorded as
 * rejected, so the developer learns why their comment did nothing: a marker that
 * silently fails is worse than no marker at all.
 *
 * SECOND, nothing here deletes a finding. This pass ANNOTATES: the finding keeps
 * flowing through the delta, the passes and the receipt, carrying the reason it
 * was dismissed. A receipt that quietly dropped a finding because a comment in
 * the repository told it to would be a hole in the evidence chain — the whole
 * claim of the artifact is that it states what was and was not flagged, and
 * "nothing was found" must never be reachable by editing a comment.
 */
const MARKER_RE = /\bcodetruss-ignore\b[ \t]*(:[ \t]*(.*))?/

/**
 * Comment terminators that would otherwise be read as part of the reason.
 * `/* codetruss-ignore: deliberate *\/` is how this gets written in JS, CSS,
 * Java and C; in HTML and Markdown it is `<!-- ... -->`.
 */
const COMMENT_CLOSE_RE = /\s*(\*\/|-->)\s*$/

/**
 * Reasons are quoted verbatim into a signed receipt that is also validated
 * against a bounded schema on sync. A reason longer than this is not a reason,
 * and the cap stops one pathological comment from making a receipt unsyncable.
 */
const MAX_REASON_LENGTH = 500

interface ParsedMarker {
  /** Text after the colon. Empty when the marker gave no reason. */
  reason: string
  /**
   * Nothing but whitespace and comment punctuation precedes the marker.
   *
   * A marker trailing a line of CODE was written about that code, so it governs
   * only its own line. Letting it reach the line below would silently dismiss a
   * neighbouring finding its author never looked at.
   */
  commentOnly: boolean
}

function parseMarker(line: string | undefined): ParsedMarker | null {
  if (line === undefined) return null
  const match = MARKER_RE.exec(line)
  if (!match) return null
  const reason = match[2] === undefined ? '' : match[2].replace(COMMENT_CLOSE_RE, '').trim().slice(0, MAX_REASON_LENGTH)
  return { reason, commentOnly: !/[A-Za-z0-9_$]/.test(line.slice(0, match.index)) }
}

/** The marker governing `line`: its own line, else a comment-only line above it. */
function markerFor(lines: string[], line: number): { reason: string; markerLine: number } | null {
  const own = parseMarker(lines[line - 1])
  if (own) return { reason: own.reason, markerLine: line }
  const above = parseMarker(lines[line - 2])
  if (above?.commentOnly) return { reason: above.reason, markerLine: line - 1 }
  return null
}

/**
 * Record on every finding whether an inline marker dismissed it.
 *
 * Returns new objects; the input is not mutated. Findings without BOTH a file
 * and a line are returned untouched: a repository-level or whole-file finding
 * has no line for a comment to sit beside, and picking one — the top of the
 * file, the first match — would suppress by guesswork.
 */
export function annotateSuppressions(findings: AnalyzerFinding[], index: RepoIndex): AnalyzerFinding[] {
  if (findings.length === 0) return findings
  const lineCache = new Map<string, string[] | null>()
  const readLines = (path: string): string[] | null => {
    const cached = lineCache.get(path)
    if (cached !== undefined) return cached
    const file = index.files.find((candidate) => candidate.path === path)
    // Generated files are read here for the reason the secret scanner reads
    // them: what the line says governs, whichever tool wrote it.
    const content = file ? file.content ?? file.excludedContent ?? null : null
    const lines = content === null ? null : content.split('\n')
    lineCache.set(path, lines)
    return lines
  }

  return findings.map((finding) => {
    if (!finding.filePath || !finding.line) return finding
    const lines = readLines(finding.filePath)
    if (!lines) return finding
    const marker = markerFor(lines, finding.line)
    if (!marker) return finding
    const suppression: FindingSuppression = {
      reason: marker.reason,
      markerLine: marker.markerLine,
      applied: marker.reason.length > 0,
    }
    return { ...finding, suppression }
  })
}
