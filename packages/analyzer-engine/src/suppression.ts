import { classifyLines } from './comments'
import { redactSecrets } from './secrets'
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
 *
 * That last sentence is a load-bearing claim, so this pass reads a marker only
 * where a HUMAN could have written one: in a comment ({@link markerIsComment}),
 * in a file this repository actually authors ({@link readFile}), and it quotes
 * back only text that carries no credential ({@link parseMarker}).
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
  // The reason runs to the end of the physical line, so on a one-line file a
  // marker written BEFORE a credential harvests the credential — and the reason
  // is quoted onto a signed receipt and synced to the hosted database. The
  // secret scanner's promise that values never leave it has to hold for text
  // this module copies out of the repository too, so it is redacted here rather
  // than trusted to be prose. Redaction runs before the cap: truncating first
  // could cut a credential short of the pattern that recognizes it.
  const raw = match[2] === undefined ? '' : match[2].replace(COMMENT_CLOSE_RE, '').trim()
  return {
    reason: redactSecrets(raw).slice(0, MAX_REASON_LENGTH),
    commentOnly: !/[A-Za-z0-9_$]/.test(line.slice(0, match.index)),
  }
}

/**
 * A file's lines, plus what each line contributes as CODE where that is knowable.
 *
 * `code` is null for a language {@link classifyLines} has no classifier for; it
 * is never an empty array, so "no classifier" and "empty file" stay distinct.
 */
interface FileLines {
  raw: string[]
  code: string[] | null
}

/**
 * Is the marker on this line written in a COMMENT?
 *
 * It has to be. `codetruss-ignore:` is otherwise honored wherever the characters
 * appear — including inside a string literal — and a minified bundle is ONE
 * physical line, so a single planted string would dismiss every finding in the
 * file. Dismissed findings stop gating the verdict, which puts a PASS one
 * planted string away: exactly what this module promises is unreachable.
 *
 * The classifier separates comments from code and from strings, so a marker is
 * in a comment precisely when it does not appear in the line's code. For a
 * language with no classifier the question cannot be answered, and the marker is
 * honored only in the placement that needs no answer — a line whose every
 * preceding character is whitespace or comment punctuation.
 */
function markerIsComment(file: FileLines, row: number, marker: ParsedMarker): boolean {
  const code = file.code?.[row]
  if (code === undefined) return marker.commentOnly
  return !MARKER_RE.test(code)
}

/** The marker governing `line`: its own line, else a comment-only line above it. */
function markerFor(file: FileLines, line: number): { reason: string; markerLine: number } | null {
  const own = parseMarker(file.raw[line - 1])
  if (own && markerIsComment(file, line - 1, own)) return { reason: own.reason, markerLine: line }
  const above = parseMarker(file.raw[line - 2])
  if (above?.commentOnly && markerIsComment(file, line - 2, above)) {
    return { reason: above.reason, markerLine: line - 1 }
  }
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
  const fileCache = new Map<string, FileLines | null>()
  const readFile = (path: string): FileLines | null => {
    const cached = fileCache.get(path)
    if (cached !== undefined) return cached
    const file = index.files.find((candidate) => candidate.path === path)
    // `content` only, never `excludedContent`. A generated, minified or vendored
    // file has no author who could have written an intentional marker, so a
    // marker found there was written by a generator or shipped by a dependency —
    // neither of which is a judgement this repository's developers made.
    const content = file?.content ?? null
    const lines =
      content === null
        ? null
        : { raw: content.split('\n'), code: codeLines(path, content) }
    fileCache.set(path, lines)
    return lines
  }

  return findings.map((finding) => {
    if (!finding.filePath || !finding.line) return finding
    const file = readFile(finding.filePath)
    if (!file) return finding
    const marker = markerFor(file, finding.line)
    if (!marker) return finding
    const suppression: FindingSuppression = {
      reason: marker.reason,
      markerLine: marker.markerLine,
      applied: marker.reason.length > 0,
    }
    return { ...finding, suppression }
  })
}

/** Per-line code text, or null when this file's language has no classifier. */
function codeLines(path: string, content: string): string[] | null {
  const classified = classifyLines(path, content)
  return classified.length === 0 ? null : classified.map((line) => line.code)
}
