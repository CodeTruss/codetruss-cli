import type { AnalyzerFinding } from '@codetruss/analyzer-engine'

/**
 * Rendering for `AnalyzerFinding.fix`.
 *
 * One rule governs every string in this module: a fix is a SUGGESTION. It was
 * not applied, it is not required, and nothing here may read as though CodeTruss
 * changed a file. The framing is repeated at the block level and again per fix
 * because the two are read in different places — the receipt section header by a
 * person, the single-line summary by an agent that may act on it immediately.
 */

const SEVERITY_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const

/** Receipts stay readable; the signed JSON always carries every fix. */
const MAX_RENDERED_FIXES = 10

/** Bound one summary line well inside the hook result's 2,000-character cap. */
const MAX_SUMMARY_CHARS = 1_200

export const FIX_DISCLAIMER =
  'Suggested changes only. CodeTruss did not apply, write, or run any of them, and a suggestion derived from one '
  + 'finding cannot see the rest of the codebase — review each change before using it.'

type FixFinding = AnalyzerFinding & { fix: NonNullable<AnalyzerFinding['fix']> }

function hasFix(finding: AnalyzerFinding): finding is FixFinding {
  return finding.fix !== undefined
}

/** Highest severity first; ties keep analyzer order so output stays stable. */
export function findingsWithFixes(findings: AnalyzerFinding[]): FixFinding[] {
  return findings
    .filter(hasFix)
    .map((finding, order) => ({ finding, order }))
    .sort((left, right) => (
      SEVERITY_RANK[right.finding.severity] - SEVERITY_RANK[left.finding.severity] || left.order - right.order
    ))
    .map((entry) => entry.finding)
}

/**
 * A fence longer than any backtick run inside the content. Fix content is often
 * Markdown that contains its own fences, and a three-backtick block would end
 * early and spill raw snippet text into the receipt body.
 */
function fenceFor(content: string): string {
  const longest = Math.max(0, ...[...content.matchAll(/`+/g)].map((match) => match[0].length))
  return '`'.repeat(Math.max(3, longest + 1))
}

function location(finding: AnalyzerFinding): string {
  if (!finding.filePath) return 'repository'
  return `\`${finding.filePath}${finding.line ? `:${finding.line}` : ''}\``
}

/**
 * The receipt's suggested-fix section, or NO LINES AT ALL when nothing carries
 * a fix. The empty case is load-bearing: receipts signed before fixes existed
 * must still render byte-for-byte, so this block may never emit a header it
 * cannot fill.
 */
export function suggestedFixLines(findings: AnalyzerFinding[]): string[] {
  const withFixes = findingsWithFixes(findings)
  if (withFixes.length === 0) return []
  const rendered = withFixes.slice(0, MAX_RENDERED_FIXES)
  const lines = [
    `## Suggested fixes (${withFixes.length})`,
    '',
    FIX_DISCLAIMER,
    '',
  ]
  for (const finding of rendered) {
    const fence = fenceFor(finding.fix.content)
    lines.push(
      `### ${finding.severity} — ${finding.title.replaceAll('\n', ' ')} (${location(finding)})`,
      '',
      finding.fix.description,
      '',
      `${fence}${finding.fix.language}`,
      ...finding.fix.content.replace(/\n$/, '').split('\n'),
      fence,
      '',
      `Before applying: ${finding.fix.safetyNote}`,
      '',
    )
  }
  if (withFixes.length > rendered.length) {
    lines.push(`${withFixes.length - rendered.length} further finding(s) carry a suggested change; the signed JSON receipt has all of them.`, '')
  }
  return lines
}

/**
 * One line for the agent-facing Stop summary: the highest-severity finding's
 * suggestion, so the agent can correct the change before a person ever reads
 * the receipt. Returns undefined when nothing carries a fix.
 */
export function topFixSuggestion(findings: AnalyzerFinding[]): string | undefined {
  const finding = findingsWithFixes(findings)[0]
  if (!finding) return undefined
  const where = finding.filePath ? ` at ${finding.filePath}${finding.line ? `:${finding.line}` : ''}` : ''
  return [
    `Suggested fix (NOT applied — review before using) for ${finding.severity} "${finding.title.replaceAll('\n', ' ')}"${where}:`,
    finding.fix.description,
    finding.fix.safetyNote,
    'The exact suggested change is in the receipt above.',
  ].join(' ').slice(0, MAX_SUMMARY_CHARS)
}
