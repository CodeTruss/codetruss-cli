/**
 * A strict JavaScript/TypeScript tokenizer.
 *
 * "Strict" is the whole point: anything this lexer cannot read with certainty
 * throws {@link ParseError}, the file is skipped, and the scan reports that as
 * missing coverage. A tokenizer that guesses would hand the rule pack a wrong
 * tree, and a wrong tree is how a security tool produces a false positive.
 *
 * Regex-vs-division is resolved by the parser, not by heuristics here: the
 * parser knows whether it is in operand or operator position and passes
 * `regexAllowed`. Template literals are likewise driven by the parser, because
 * `${...}` nests arbitrary expressions.
 */

export class ParseError extends Error {}

export type TokenKind =
  | 'identifier'
  | 'private'
  | 'number'
  | 'string'
  | 'regex'
  | 'punct'
  | 'template_start'
  | 'eof'

export interface Token {
  kind: TokenKind
  start: number
  end: number
  /** Punctuator/identifier text; empty for literals (read the span instead). */
  value: string
  /** A line terminator appeared between the previous token and this one. */
  newlineBefore: boolean
}

const PUNCTUATORS: string[] = [
  '>>>=',
  '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--',
  '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>',
  '{', '}', '(', ')', '[', ']', ';', ',', '<', '>', '+', '-', '*', '/', '%',
  '&', '|', '^', '!', '~', '?', ':', '=', '.', '@',
]

function isIdStart(code: number): boolean {
  return (
    (code >= 97 && code <= 122) || // a-z
    (code >= 65 && code <= 90) || // A-Z
    code === 36 || // $
    code === 95 || // _
    code >= 0x80
  )
}

function isIdPart(code: number): boolean {
  return isIdStart(code) || (code >= 48 && code <= 57)
}

function isLineTerminator(code: number): boolean {
  return code === 10 || code === 13 || code === 0x2028 || code === 0x2029
}

function isSpace(code: number): boolean {
  return (
    code === 32 ||
    code === 9 ||
    code === 11 ||
    code === 12 ||
    code === 0xa0 ||
    code === 0xfeff ||
    (code >= 0x1680 && /\s/.test(String.fromCharCode(code)))
  )
}

export interface CommentSpan {
  start: number
  end: number
}

export class Lexer {
  readonly text: string
  pos = 0
  /** Comments seen anywhere during lexing, keyed by start offset (dedupes
   *  re-lexing during the parser's speculative scans). */
  readonly comments = new Map<number, CommentSpan>()
  /** Discovery order of {@link comments}. Speculative scans can look ahead and
   *  record a later comment before an earlier one, so the parser sorts when
   *  {@link commentsUnsorted} is set rather than on every flush. */
  readonly commentList: CommentSpan[] = []
  commentsUnsorted = false

  private recordComment(start: number, end: number): void {
    if (this.comments.has(start)) return
    const span = { start, end }
    this.comments.set(start, span)
    const last = this.commentList[this.commentList.length - 1]
    if (last && last.start > start) this.commentsUnsorted = true
    this.commentList.push(span)
  }

  constructor(text: string) {
    this.text = text
    // A hashbang is only legal on line 1 and is not a comment node.
    if (text.startsWith('#!')) {
      while (this.pos < text.length && !isLineTerminator(text.charCodeAt(this.pos))) this.pos++
    }
  }

  /** Skip whitespace and comments; returns true when a line break was crossed. */
  private skipTrivia(): boolean {
    let newline = false
    const text = this.text
    while (this.pos < text.length) {
      const code = text.charCodeAt(this.pos)
      if (isLineTerminator(code)) {
        newline = true
        this.pos++
        continue
      }
      if (isSpace(code)) {
        this.pos++
        continue
      }
      if (code === 47 /* / */) {
        const next = text.charCodeAt(this.pos + 1)
        if (next === 47 /* / */) {
          const start = this.pos
          this.pos += 2
          while (this.pos < text.length && !isLineTerminator(text.charCodeAt(this.pos))) this.pos++
          this.recordComment(start, this.pos)
          continue
        }
        if (next === 42 /* * */) {
          const start = this.pos
          this.pos += 2
          for (;;) {
            if (this.pos >= text.length) throw new ParseError('unterminated block comment')
            if (text.charCodeAt(this.pos) === 42 && text.charCodeAt(this.pos + 1) === 47) {
              this.pos += 2
              break
            }
            if (isLineTerminator(text.charCodeAt(this.pos))) newline = true
            this.pos++
          }
          this.recordComment(start, this.pos)
          continue
        }
      }
      break
    }
    return newline
  }

  /**
   * Advance past whitespace and comments WITHOUT producing a token, and return
   * the resulting offset. JSX attribute values must be classified from the raw
   * character (a multi-line `class="…"` is markup, not a JS string literal), so
   * the caller has to look before it lexes.
   */
  peekPosition(): number {
    this.skipTrivia()
    return this.pos
  }

  /** Read the next token. `regexAllowed` decides `/` — regex or division. */
  next(regexAllowed: boolean): Token {
    const newlineBefore = this.skipTrivia()
    const text = this.text
    const start = this.pos
    if (start >= text.length) {
      return { kind: 'eof', start, end: start, value: '', newlineBefore }
    }
    const code = text.charCodeAt(start)

    if (isIdStart(code)) {
      if (code === 92 /* \ */) throw new ParseError(`unicode escape in identifier at ${start}`)
      this.pos++
      while (this.pos < text.length && isIdPart(text.charCodeAt(this.pos))) this.pos++
      return { kind: 'identifier', start, end: this.pos, value: text.slice(start, this.pos), newlineBefore }
    }
    if (code === 92 /* \ */) throw new ParseError(`unicode escape in identifier at ${start}`)

    if (code === 35 /* # */) {
      this.pos++
      if (!isIdStart(text.charCodeAt(this.pos))) throw new ParseError(`bad private name at ${start}`)
      while (this.pos < text.length && isIdPart(text.charCodeAt(this.pos))) this.pos++
      return { kind: 'private', start, end: this.pos, value: text.slice(start, this.pos), newlineBefore }
    }

    if ((code >= 48 && code <= 57) || (code === 46 && text.charCodeAt(start + 1) >= 48 && text.charCodeAt(start + 1) <= 57)) {
      return { kind: 'number', start, end: this.readNumber(), value: '', newlineBefore }
    }

    if (code === 34 || code === 39) {
      return { kind: 'string', start, end: this.readString(code), value: '', newlineBefore }
    }

    if (code === 96 /* ` */) {
      this.pos++
      return { kind: 'template_start', start, end: this.pos, value: '`', newlineBefore }
    }

    if (code === 47 /* / */ && regexAllowed) {
      return { kind: 'regex', start, end: this.readRegex(), value: '', newlineBefore }
    }

    for (const punct of PUNCTUATORS) {
      if (text.startsWith(punct, start)) {
        // `?.3` is a conditional followed by a number, not optional chaining.
        if (punct === '?.' && text.charCodeAt(start + 2) >= 48 && text.charCodeAt(start + 2) <= 57) continue
        this.pos = start + punct.length
        return { kind: 'punct', start, end: this.pos, value: punct, newlineBefore }
      }
    }

    throw new ParseError(`unexpected character ${JSON.stringify(text[start])} at ${start}`)
  }

  private readNumber(): number {
    const text = this.text
    let i = this.pos
    if (text.charCodeAt(i) === 48 /* 0 */ && /[xXoObB]/.test(text[i + 1] ?? '')) {
      // One digit class covers hex/octal/binary: the grammar of the radix is not
      // this scanner's problem, only where the literal ends.
      i += 2
      while (i < text.length && /[0-9a-fA-F_]/.test(text[i]!)) i++
    } else {
      while (i < text.length && /[0-9_]/.test(text[i]!)) i++
      if (text[i] === '.') {
        i++
        while (i < text.length && /[0-9_]/.test(text[i]!)) i++
      }
      if (/[eE]/.test(text[i] ?? '')) {
        i++
        if (/[+-]/.test(text[i] ?? '')) i++
        if (!/[0-9]/.test(text[i] ?? '')) throw new ParseError('bad exponent')
        while (i < text.length && /[0-9_]/.test(text[i]!)) i++
      }
    }
    if (text[i] === 'n') i++ // bigint
    if (i === this.pos) throw new ParseError(`bad numeric literal at ${i}`)
    if (isIdStart(text.charCodeAt(i))) throw new ParseError(`numeric literal followed by identifier at ${i}`)
    this.pos = i
    return i
  }

  private readString(quote: number): number {
    const text = this.text
    let i = this.pos + 1
    for (;;) {
      if (i >= text.length) throw new ParseError(`unterminated string at ${i}`)
      const code = text.charCodeAt(i)
      if (code === 92 /* \ */) {
        // A backslash-newline is a line continuation; anything else is one escape.
        i += 2
        if (text.charCodeAt(i - 1) === 13 && text.charCodeAt(i) === 10) i++
        continue
      }
      if (code === quote) {
        i++
        break
      }
      if (isLineTerminator(code)) throw new ParseError(`newline in string literal at ${i}`)
      i++
    }
    this.pos = i
    return i
  }

  private readRegex(): number {
    const text = this.text
    let i = this.pos + 1
    let inClass = false
    for (;;) {
      if (i >= text.length) throw new ParseError('unterminated regex')
      const code = text.charCodeAt(i)
      if (isLineTerminator(code)) throw new ParseError('newline in regex')
      if (code === 92 /* \ */) {
        i += 2
        continue
      }
      if (code === 91 /* [ */) inClass = true
      else if (code === 93 /* ] */) inClass = false
      else if (code === 47 /* / */ && !inClass) {
        i++
        break
      }
      i++
    }
    while (i < text.length && isIdPart(text.charCodeAt(i))) i++
    this.pos = i
    return i
  }

  /**
   * Scan one raw chunk of a template literal starting at `from` (just past a
   * backtick or a substitution's `}`). Returns where the literal text ends and
   * whether a `${` substitution or the closing backtick terminated it.
   */
  templateChunk(from: number): { fragmentEnd: number; kind: 'substitution' | 'end' } {
    const text = this.text
    let i = from
    for (;;) {
      if (i >= text.length) throw new ParseError('unterminated template literal')
      const code = text.charCodeAt(i)
      if (code === 92 /* \ */) {
        i += 2
        continue
      }
      if (code === 96 /* ` */) return { fragmentEnd: i, kind: 'end' }
      if (code === 36 /* $ */ && text.charCodeAt(i + 1) === 123 /* { */) {
        return { fragmentEnd: i, kind: 'substitution' }
      }
      i++
    }
  }
}
