import type { SastLanguage } from './lang'

/**
 * What the CLI's local SAST pass is allowed to report.
 *
 * The engine's full pack is 22 rules across 10 languages. The CLI runs a
 * deliberate SUBSET, and the subset is a precision decision, not a packaging
 * one: every rule listed here has been differentially validated — same rule,
 * same file, zero disagreement against the hosted tree-sitter parser — across
 * the real-repository corpus, and adjudicated to zero false positives. A rule
 * earns its way into this list; it is not added because it compiles.
 *
 * The five AI-agent defect rules are the classes coding agents actually get
 * wrong (floating writes, swallowed errors, coercion comparisons, N+1 loops,
 * mass assignment). `sql-injection` is the one injection class that reaches a
 * sink through plain string building, so it survives without the hosted symbol
 * graph.
 */
export const CLI_SAST_RULE_IDS: ReadonlySet<string> = new Set([
  'unawaited-persistence',
  'swallowed-error',
  'loose-equality',
  'db-call-in-loop',
  'mass-assignment',
  'open-record-write',
  'sql-injection',
])

/** Languages the CLI's zero-dependency parser covers. */
export const CLI_SAST_LANGUAGES: ReadonlySet<SastLanguage> = new Set<SastLanguage>([
  'javascript',
  'typescript',
  'tsx',
])

/** Display names of {@link CLI_SAST_LANGUAGES}, matching the indexer's labels. */
export const CLI_SAST_LANGUAGE_NAMES: ReadonlySet<string> = new Set(['TypeScript', 'JavaScript'])

/**
 * Classes the local pass STILL does not check, named so a receipt can say so.
 *
 * This is the honest complement of {@link CLI_SAST_RULE_IDS}: the CLI gained
 * concat-SQL-injection but not command injection, path traversal, SSRF, XSS,
 * open redirect or insecure deserialization, because those need either the
 * hosted symbol graph or rules that have not cleared the same precision bar
 * locally. A receipt that listed only what ran would repeat the exact mistake
 * the coverage analyzer exists to prevent.
 */
export const CLI_SAST_UNCHECKED_CLASSES = [
  'command injection',
  'code injection',
  'path traversal',
  'SSRF',
  'open redirect',
  'XSS',
  'insecure deserialization',
] as const
