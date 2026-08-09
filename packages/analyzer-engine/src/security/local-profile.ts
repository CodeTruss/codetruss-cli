
/**
 * What the CLI's local SAST pass is allowed to report.
 *
 * The engine's full pack is 22 rules across 10 languages. The CLI runs a
 * deliberate SUBSET, and the subset is a precision decision, not a packaging
 * one: every rule listed here has been differentially validated — same rule,
 * same file, zero disagreement against the hosted tree-sitter parser — across
 * the real-repository corpus. A rule earns its way into this list; it is not
 * added because it compiles.
 *
 * CORRECTION (0.2.53). This comment used to end "and adjudicated to zero false
 * positives". That was true of the eight-repository corpus it was written
 * against and false as a general claim, and the difference mattered: on a
 * ten-repository corpus nobody here chose, `sql-injection` reported drizzle's
 * `db.execute(sql`…`)` — bound parameters, the documented safe construction —
 * as CRITICAL "untrusted input is concatenated", and missed a genuinely dynamic
 * `client.query(query)` in the same run. Both are fixed. The claim this comment
 * now makes is the narrower one it can support: differential parser validation,
 * plus whatever the published corpus measurements say on the day you read them.
 * A zero adjudicated on a corpus we picked is a property of the corpus.
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
