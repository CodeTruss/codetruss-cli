/**
 * Per-line comment classification, shared by the comment-shape analyzers.
 *
 * `IndexedFile.loc` counts non-blank lines and is NOT comment-stripped, so any
 * rule that reasons about commenting has to compute its own code/comment split.
 * A naive block tracker gets this wrong in ways that matter: a file holding six
 * pasted query plans inside `/* … *\/` blocks measures as almost pure comment,
 * and flagging it would punish the single most deliberate file in a repository.
 *
 * The classifier is a character scanner rather than a set of line regexes
 * because `//` inside a URL, a template literal spanning lines, and a block
 * comment opened and closed on one line all defeat line-at-a-time matching.
 *
 * Known limit: a regex literal containing `/*` (`/a\/*b/`) is read as opening a
 * block comment. Widening the scanner to track regex-vs-division context needs
 * expression state this pass does not keep, and the shape is vanishingly rare
 * next to the string and template cases it does handle.
 */

/** How a line reads once comments and strings are separated from code. */
export type CommentLineKind = 'blank' | 'code' | 'line' | 'block' | 'doc'

export interface ClassifiedLine {
  kind: CommentLineKind
  /** Comment prose with markers stripped. Empty on code and blank lines. */
  text: string
  /** Code with any trailing comment removed. Empty on comment and blank lines. */
  code: string
  /** Id of the block comment covering this line, or -1 outside one. */
  block: number
}

/** The comment syntax families this pass understands. */
type Syntax = 'c-like' | 'python'

/**
 * Extensions with a classifier. Everything else returns no lines and is
 * silently out of scope — the analyzers simply do not claim coverage they lack.
 */
const SYNTAX_BY_EXTENSION: Record<string, Syntax> = {
  '.ts': 'c-like',
  '.tsx': 'c-like',
  '.js': 'c-like',
  '.jsx': 'c-like',
  '.mjs': 'c-like',
  '.cjs': 'c-like',
  '.go': 'c-like',
  '.rs': 'c-like',
  '.java': 'c-like',
  '.cs': 'c-like',
  '.py': 'python',
}

export function commentSyntaxFor(path: string): Syntax | null {
  const dot = path.lastIndexOf('.')
  if (dot === -1) return null
  return SYNTAX_BY_EXTENSION[path.slice(dot).toLowerCase()] ?? null
}

type ScanState =
  | 'code'
  | 'line-comment'
  | 'block-comment'
  | 'single'
  | 'double'
  | 'template'
  | 'py-triple-double'
  | 'py-triple-single'

interface LineScan {
  /** What the first non-whitespace character on the line belongs to. */
  first: CommentLineKind
  /** The line's characters that are code, with comment spans blanked out. */
  code: string
  block: number
}

/**
 * Everything the scanner carries. State that survives a newline (an open block
 * comment, a template literal) sits beside per-line state, because the whole
 * point of a scanner over line regexes is that the two interact.
 */
interface Scanner {
  syntax: Syntax
  state: ScanState
  docBlock: boolean
  blockId: number
  blockCounter: number
  /** The leading token of the current line has been classified. */
  seen: boolean
  /** Code text accumulated for the current line, comment spans omitted. */
  code: string
  scan: LineScan
}

function isSpace(char: string): boolean {
  return char === ' ' || char === '\t' || char === '\r'
}

/** Record what the line's leading token is, the first time one is seen. */
function openLine(s: Scanner, kind: CommentLineKind, block: number): void {
  if (s.seen) return
  s.scan.first = kind
  s.scan.block = block
  s.seen = true
}

function openBlock(s: Scanner, doc: boolean): void {
  s.docBlock = doc
  s.blockId = s.blockCounter++
  openLine(s, doc ? 'doc' : 'block', s.blockId)
}

function closeBlock(s: Scanner): void {
  s.state = 'code'
  s.docBlock = false
  s.blockId = -1
}

/** One character in `code` state. Returns the column to resume at. */
function stepCode(s: Scanner, line: string, col: number): number {
  const char = line[col]
  const next = line[col + 1]
  if (isSpace(char)) {
    s.code += char
    return col
  }
  if (s.syntax === 'c-like' && char === '/' && next === '/') {
    const third = line[col + 2]
    openLine(s, third === '/' || third === '!' ? 'doc' : 'line', -1)
    s.state = 'line-comment'
    return col
  }
  if (s.syntax === 'c-like' && char === '/' && next === '*') {
    // `/**` opens a doc block, but `/**/` is an empty ordinary comment.
    openBlock(s, line[col + 2] === '*' && line[col + 3] !== '/')
    s.state = 'block-comment'
    return col + 1
  }
  if (s.syntax === 'python' && char === '#') {
    openLine(s, 'line', -1)
    s.state = 'line-comment'
    return col
  }
  if (s.syntax === 'python' && (char === '"' || char === "'") && next === char && line[col + 2] === char) {
    // A triple-quoted string opening a statement is a docstring; one used as a
    // value is an ordinary string and counts as code.
    if (s.seen) {
      s.docBlock = false
      s.code += char
    } else {
      openBlock(s, true)
    }
    s.seen = true
    s.state = char === '"' ? 'py-triple-double' : 'py-triple-single'
    return col + 2
  }
  openLine(s, 'code', -1)
  s.code += char
  if (char === "'") s.state = 'single'
  else if (char === '"') s.state = 'double'
  else if (char === '`' && s.syntax === 'c-like') s.state = 'template'
  return col
}

/** One character inside a `/* … *\/` block. */
function stepBlock(s: Scanner, line: string, col: number): number {
  const char = line[col]
  if (!isSpace(char)) openLine(s, s.docBlock ? 'doc' : 'block', s.blockId)
  if (char === '*' && line[col + 1] === '/') {
    closeBlock(s)
    return col + 1
  }
  return col
}

/** One character inside a Python triple-quoted string. */
function stepTriple(s: Scanner, line: string, col: number): number {
  const char = line[col]
  const quote = s.state === 'py-triple-double' ? '"' : "'"
  if (!isSpace(char) && !s.seen) {
    if (s.docBlock) openLine(s, 'doc', s.blockId)
    else {
      openLine(s, 'code', -1)
      s.code += char
    }
  }
  if (char === quote && line[col + 1] === quote && line[col + 2] === quote) {
    closeBlock(s)
    return col + 2
  }
  return col
}

/** One character inside an ordinary string or template literal. */
function stepString(s: Scanner, line: string, col: number): number {
  const char = line[col]
  // An escape consumes the character after it, so a `\'` never closes the literal.
  if (char === '\\') {
    s.code += char + (line[col + 1] ?? '')
    return col + 1
  }
  s.code += char
  const quote = s.state === 'single' ? "'" : s.state === 'double' ? '"' : '`'
  if (char === quote) s.state = 'code'
  return col
}

function scanLine(s: Scanner, line: string): void {
  for (let col = 0; col < line.length; col++) {
    if (s.state === 'code') col = stepCode(s, line, col)
    else if (s.state === 'block-comment') col = stepBlock(s, line, col)
    else if (s.state === 'py-triple-double' || s.state === 'py-triple-single') col = stepTriple(s, line, col)
    else if (s.state !== 'line-comment') col = stepString(s, line, col)
    // `line-comment` runs to the end of the line and contributes nothing.
  }
  s.scan.code = s.code
  // A line comment ends at the newline; every multi-line state carries over. An
  // unterminated single-line string is a syntax error, not a continuation.
  if (s.state === 'line-comment' || s.state === 'single' || s.state === 'double') s.state = 'code'
}

/**
 * Split a file into classified lines.
 *
 * Returns an empty array for a language with no classifier, which callers read
 * as "not analyzable" rather than "no comments".
 */
export function classifyLines(path: string, content: string): ClassifiedLine[] {
  const syntax = commentSyntaxFor(path)
  if (!syntax) return []

  const raw = content.split('\n')
  const scans: LineScan[] = raw.map(() => ({ first: 'blank' as CommentLineKind, code: '', block: -1 }))
  const scanner: Scanner = {
    syntax, state: 'code', docBlock: false, blockId: -1, blockCounter: 0,
    seen: false, code: '', scan: scans[0],
  }

  for (let row = 0; row < raw.length; row++) {
    scanner.scan = scans[row]
    scanner.seen = false
    scanner.code = ''
    scanLine(scanner, raw[row])
  }

  return raw.map((line, row) => {
    const scan = scans[row]
    if (line.trim().length === 0) return { kind: 'blank' as const, text: '', code: '', block: -1 }
    if (scan.code.trim().length > 0) return { kind: 'code' as const, text: '', code: scan.code.trim(), block: -1 }
    if (scan.first === 'code' || scan.first === 'blank') return { kind: 'code' as const, text: '', code: line.trim(), block: -1 }
    return { kind: scan.first, text: stripMarkers(line), code: '', block: scan.block }
  })
}

/** Remove comment punctuation so only the prose is compared. */
function stripMarkers(line: string): string {
  return line
    .trim()
    .replace(/^\/\*+!?/, '')
    .replace(/^\/\/+[!]?/, '')
    .replace(/^#+/, '')
    .replace(/^("""|''')/, '')
    .replace(/("""|''')$/, '')
    .replace(/\*\/\s*$/, '')
    .replace(/^\*+/, '')
    .trim()
}

/**
 * A block comment holding pasted evidence rather than commentary.
 *
 * Measured against a real file preserving six `EXPLAIN ANALYZE` plans: at a
 * comment-to-code ratio of 1.07 it is the most defensible file in its
 * repository, and any rule that counts those lines as commentary flags it.
 */
const DATA_BLOCK_MIN_LINES = 3
const DATA_BLOCK_NON_PROSE_RATIO = 0.3

function nonProse(text: string): boolean {
  if (text.length === 0) return false
  return /^(?:->|\||[-=+_*]{3,}|[^A-Za-z])/.test(text)
}

/** Ids of block comments that read as pasted data, not prose. */
export function dataBlockIds(lines: ClassifiedLine[]): Set<number> {
  const blocks = new Map<number, string[]>()
  for (const line of lines) {
    if (line.block === -1 || (line.kind !== 'block' && line.kind !== 'doc')) continue
    const bucket = blocks.get(line.block)
    if (bucket) bucket.push(line.text)
    else blocks.set(line.block, [line.text])
  }
  const dataBlocks = new Set<number>()
  for (const [id, texts] of blocks) {
    if (texts.length < DATA_BLOCK_MIN_LINES) continue
    const nonProseCount = texts.filter(nonProse).length
    if (nonProseCount / texts.length >= DATA_BLOCK_NON_PROSE_RATIO) dataBlocks.add(id)
  }
  return dataBlocks
}

/**
 * Words a comment and a line of code can be compared on: identifiers split on
 * camelCase and separators, lowercased, with filler removed. Non-Latin comments
 * yield fewer than two tokens and therefore never compare as redundant.
 */
const STOPWORDS = new Set([
  'the', 'and', 'but', 'for', 'not', 'are', 'was', 'were', 'been', 'being',
  'this', 'that', 'these', 'those', 'its', 'with', 'from', 'into', 'onto',
  'they', 'them', 'their', 'our', 'your', 'you', 'we', 'it', 'is', 'be',
  'will', 'would', 'can', 'could', 'should', 'may', 'might', 'must', 'shall',
  'does', 'did', 'has', 'have', 'had', 'all', 'any', 'each', 'every',
  'when', 'while', 'then', 'else', 'than', 'there', 'here', 'over', 'under',
  'out', 'off', 'via', 'per', 'own', 'new', 'old', 'only', 'also', 'just',
  'now', 'one', 'two', 'use', 'used', 'using', 'let', 'via',
])

export function contentWords(text: string): Set<string> {
  const words = new Set<string>()
  for (const chunk of text.split(/[^A-Za-z0-9]+/)) {
    if (!chunk) continue
    for (const token of chunk.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/\s+/)) {
      const word = token.toLowerCase()
      if (word.length < 3 || STOPWORDS.has(word)) continue
      words.add(word)
    }
  }
  return words
}
