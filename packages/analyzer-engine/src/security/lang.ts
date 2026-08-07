/**
 * Language vocabulary and the parser contract the SAST engine analyzes against.
 *
 * The engine owns rules, taint and findings; it does NOT own a parser. Every
 * front-end injects one:
 *
 *  - the hosted app injects `web-tree-sitter` + the prebuilt WASM grammars
 *    (10 languages, full fidelity), and
 *  - the CLI injects the zero-dependency JS-family parser in `js-parse/`,
 *    because the WASM grammars are 6x the CLI's entire 1 MB release budget.
 *
 * Both produce the SAME node vocabulary — tree-sitter's grammar node names —
 * so one rule pack runs unchanged behind either. {@link SyntaxNode} is the
 * structural subset of `web-tree-sitter`'s `SyntaxNode` the rules actually
 * touch; the real thing satisfies it as-is, with no adapter.
 */

/** Languages with a grammar somewhere in the product and at least one rule. */
export type SastLanguage =
  | 'javascript'
  | 'typescript'
  | 'tsx'
  | 'python'
  | 'java'
  | 'csharp'
  | 'go'
  | 'php'
  | 'ruby'
  | 'rust'

const EXT_LANG: Record<string, SastLanguage> = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.tsx': 'tsx',
  '.py': 'python',
  '.pyi': 'python',
  '.java': 'java',
  '.cs': 'csharp',
  '.go': 'go',
  '.php': 'php',
  '.rb': 'ruby',
  '.rs': 'rust',
}

/** Language for a path, or null when the extension isn't SAST-covered. */
export function sastLanguageForPath(path: string): SastLanguage | null {
  const dot = path.lastIndexOf('.')
  if (dot === -1) return null
  return EXT_LANG[path.slice(dot).toLowerCase()] ?? null
}

/** JS-family languages share one adapter. */
export function isJsFamily(lang: SastLanguage): boolean {
  return lang === 'javascript' || lang === 'typescript' || lang === 'tsx'
}

// ---- bounds ---------------------------------------------------------------
export const MAX_SOURCE_BYTES = 400_000
export const MAX_NODES = 400_000

/**
 * The subset of a tree-sitter `SyntaxNode` the rule pack and taint engine read.
 *
 * Deliberately structural and minimal: anything an injected parser must
 * implement is listed here, and nothing else may be relied on. `web-tree-sitter`
 * satisfies this interface without a wrapper, which is what keeps the hosted
 * path byte-for-byte unchanged by the extraction.
 */
export interface SyntaxNode {
  readonly type: string
  readonly text: string
  readonly isNamed: boolean
  /** Identity token. Node wrappers are not reference-stable, so rules compare ids. */
  readonly id: number
  readonly startIndex: number
  readonly endIndex: number
  readonly startPosition: { row: number; column: number }
  readonly endPosition: { row: number; column: number }
  readonly parent: SyntaxNode | null
  readonly children: SyntaxNode[]
  readonly namedChildren: SyntaxNode[]
  readonly childCount: number
  readonly namedChildCount: number
  readonly previousNamedSibling: SyntaxNode | null
  readonly nextNamedSibling: SyntaxNode | null
  child(index: number): SyntaxNode | null
  childForFieldName(fieldName: string): SyntaxNode | null
}

/** A parsed file: the root node plus whether the parse recovered from errors. */
export interface ParsedTree {
  rootNode: SyntaxNode
  /** True when the parse produced error nodes (best-effort results still usable). */
  hasError: boolean
  /** Release parser-owned memory. No-op for parsers with none. */
  release(): void
}

/**
 * The injected parser.
 *
 * Contract: `parse` returns null — never throws, never guesses — when the
 * source is too large, the grammar is unavailable, or the input is outside the
 * syntax this parser handles soundly. A null is a *coverage* answer, and the
 * engine reports that language as degraded. That is what lets the zero-dep
 * parser be strict: anything it cannot parse with certainty becomes a missing
 * finding, never a wrong one.
 */
export interface SastParser {
  /** Languages this parser can produce trees for. */
  readonly languages: ReadonlySet<SastLanguage>
  parse(lang: SastLanguage, content: string): Promise<ParsedTree | null>
}
