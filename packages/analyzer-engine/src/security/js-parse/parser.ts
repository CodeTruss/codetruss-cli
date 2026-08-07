import { JsNode, Source } from './node'
import { Lexer, ParseError, type Token } from './lexer'

/**
 * A recursive-descent JavaScript/TypeScript/JSX parser that emits
 * tree-sitter-grammar node names.
 *
 * WHY: the SAST rule pack is written against tree-sitter's JS/TS vocabulary
 * (`expression_statement`, `catch_clause`, `for_in_statement`, `spread_element`,
 * …). The WASM grammars that produce it are 6 MB — six times the CLI's entire
 * release budget. Producing the *same vocabulary* from a ~40 KB parser lets the
 * identical rules, taint solver and tests run locally, instead of a second,
 * separately-drifting implementation of every rule.
 *
 * SOUNDNESS: this parser is strict where tree-sitter is error-tolerant. Any
 * construct it cannot represent faithfully throws, the file is skipped, and the
 * engine reports the language as degraded. Unsupported syntax therefore costs a
 * finding we never make — never a finding we make wrongly. That asymmetry is the
 * reason a hand-written parser can be trusted behind a zero-false-positive bar.
 *
 * Divergences from tree-sitter that are deliberate and rule-neutral:
 *  - `if_statement`'s `alternative` points straight at the else statement rather
 *    than through an `else_clause` wrapper.
 *  - TypeScript type syntax is captured as an opaque `type_annotation` /
 *    `type_arguments` span rather than a parsed type tree. The rules only ever
 *    read `type_annotation.text`.
 */

const KEYWORD_LITERALS = new Set(['true', 'false', 'null'])
/**
 * Words that can never be a binding name. Deliberately NOT the statement-starter
 * list: `type`, `async`, `interface` and friends start declarations but are also
 * ordinary identifiers, and treating them as reserved loses every
 * `list.map(type => …)`.
 */
const RESERVED_WORDS = new Set([
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default',
  'delete', 'do', 'else', 'enum', 'export', 'extends', 'false', 'finally', 'for',
  'function', 'if', 'import', 'in', 'instanceof', 'new', 'null', 'return',
  'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof', 'var', 'void',
  'while', 'with',
])
/** Binary operators by precedence (higher binds tighter). */
const BINARY_PRECEDENCE: Record<string, number> = {
  '??': 1,
  '||': 2,
  '&&': 3,
  '|': 4,
  '^': 5,
  '&': 6,
  '==': 7, '!=': 7, '===': 7, '!==': 7,
  '<': 8, '>': 8, '<=': 8, '>=': 8, instanceof: 8, in: 8,
  '<<': 9, '>>': 9, '>>>': 9,
  '+': 10, '-': 10,
  '*': 11, '/': 11, '%': 11,
  '**': 12,
}

const ASSIGN_OPS = new Set([
  '+=', '-=', '*=', '/=', '%=', '**=', '<<=', '>>=', '>>>=', '&=', '|=', '^=', '&&=', '||=', '??=',
])

const MODIFIER_KEYWORDS = new Set([
  'public', 'private', 'protected', 'readonly', 'static', 'abstract', 'override', 'declare', 'accessor',
])

/** After one of these, more type syntax must follow. */
const TYPE_OPERATOR_TOKENS = new Set([
  '|', '&', '=>', '<', ',', '?', ':', '(', '[', '{', '.', '-', '+', '...',
  'extends', 'keyof', 'typeof', 'readonly', 'infer', 'is', 'in', 'new', 'asserts', 'out', 'const', 'import',
])
/**
 * Words that may legally follow a COMPLETE type and continue it.
 *
 * `as` is deliberately absent: at depth 0 it is the expression-level operator in
 * `x as unknown as Y`, and swallowing it would make the second cast disappear.
 * Mapped-type `as` clauses only occur inside `[...]`, where depth > 0.
 */
const TYPE_CONTINUATION_WORDS = new Set(['extends', 'is', 'in'])

export type JsDialect = 'javascript' | 'typescript' | 'tsx'

interface SavedState {
  pos: number
  token: Token
  prevEnd: number
  /**
   * Speculative parses (arrow-function lookahead, generic-vs-less-than) can
   * descend into real sub-parses that attach comments. Rolling the comment
   * watermark back with the lexer is what keeps a discarded attempt from
   * consuming a comment the committed parse still needs — a swallowed comment
   * turns `catch { /* intentional *\/ }` back into an empty catch, which is a
   * false positive.
   */
  commentFlushedTo: number
}

export function parseJs(text: string, dialect: JsDialect): JsNode {
  return new Parser(text, dialect).parseProgram()
}

class Parser {
  private readonly source: Source
  private readonly lexer: Lexer
  private readonly dialect: JsDialect
  private readonly jsx: boolean
  private token: Token
  private nextId = 1
  private commentCursor = 0
  private commentFlushedTo = 0
  private commentCursorDirty = false
  private depth = 0

  constructor(text: string, dialect: JsDialect) {
    this.source = new Source(text)
    this.lexer = new Lexer(text)
    this.dialect = dialect
    this.jsx = dialect !== 'typescript'
    this.token = this.lexer.next(false)
  }

  // ---- node plumbing -------------------------------------------------------

  private make(type: string, start: number, end: number, isNamed = true): JsNode {
    return new JsNode(this.source, type, isNamed, start, end, this.nextId++)
  }

  private open(type: string, start = this.token.start): JsNode {
    return this.make(type, start, start)
  }

  private close(node: JsNode, end = this.prevEnd): JsNode {
    node.endIndex = end
    return node
  }

  private prevEnd = 0

  // ---- token plumbing ------------------------------------------------------

  private advance(): void {
    this.prevEnd = this.token.end
    this.token = this.lexer.next(false)
  }

  private save(): SavedState {
    return {
      pos: this.lexer.pos,
      token: this.token,
      prevEnd: this.prevEnd,
      commentFlushedTo: this.commentFlushedTo,
    }
  }

  private restore(state: SavedState): void {
    this.lexer.pos = state.pos
    this.token = state.token
    this.prevEnd = state.prevEnd
    if (state.commentFlushedTo !== this.commentFlushedTo) {
      this.commentFlushedTo = state.commentFlushedTo
      this.commentCursorDirty = true
    }
  }

  private is(value: string): boolean {
    return this.token.kind === 'punct' && this.token.value === value
  }

  private isWord(value: string): boolean {
    return this.token.kind === 'identifier' && this.token.value === value
  }

  /** Method form so control-flow narrowing of `this.token` cannot go stale
   *  across the many calls that advance it. */
  private atEof(): boolean {
    return this.token.kind === 'eof'
  }

  private atTemplate(): boolean {
    return this.token.kind === 'template_start'
  }

  /** Attach the current token to `parent` as an anonymous child and advance. */
  private take(parent: JsNode, field?: string): JsNode {
    const node = this.make(this.token.value || this.token.kind, this.token.start, this.token.end, false)
    parent.add(node, field)
    this.advance()
    return node
  }

  private eat(value: string, parent: JsNode, field?: string): boolean {
    if (!this.is(value)) return false
    this.take(parent, field)
    return true
  }

  private eatWord(value: string, parent: JsNode, field?: string): boolean {
    if (!this.isWord(value)) return false
    this.take(parent, field)
    return true
  }

  private expect(value: string, parent: JsNode, field?: string): void {
    if (!this.is(value)) throw new ParseError(`expected "${value}" at ${this.token.start}`)
    this.take(parent, field)
  }

  private expectWord(value: string, parent: JsNode, field?: string): void {
    if (!this.isWord(value)) throw new ParseError(`expected "${value}" at ${this.token.start}`)
    this.take(parent, field)
  }

  /** Re-read the current token allowing a regex literal (operand position). */
  private relexAsRegex(): void {
    this.lexer.pos = this.token.start
    this.token = this.lexer.next(true)
  }

  private enter(): void {
    if (++this.depth > 400) throw new ParseError('expression nesting too deep')
  }

  private exit(): void {
    this.depth--
  }

  // ---- comments ------------------------------------------------------------

  /**
   * Attach every comment discovered before `until` as a named `comment` child.
   *
   * Comment placement is load-bearing: `catch { /* ignore *\/ }` must not read as
   * an empty catch, and a comment above a `try` documents intent. Attaching a
   * comment can only ever SUPPRESS a finding, so an imprecise placement costs
   * recall, not precision.
   */
  private flushComments(parent: JsNode, until = this.token.start): void {
    const list = this.lexer.commentList
    if (this.lexer.commentsUnsorted) {
      list.sort((a, b) => a.start - b.start)
      this.lexer.commentsUnsorted = false
      this.commentCursorDirty = true
    }
    if (this.commentCursorDirty) {
      this.commentCursor = 0
      while (this.commentCursor < list.length && list[this.commentCursor].start < this.commentFlushedTo) {
        this.commentCursor++
      }
      this.commentCursorDirty = false
    }
    while (this.commentCursor < list.length && list[this.commentCursor].start < until) {
      const span = list[this.commentCursor++]
      if (span.start >= this.commentFlushedTo) parent.add(this.make('comment', span.start, span.end))
    }
    if (until > this.commentFlushedTo) this.commentFlushedTo = until
  }

  // ---- program -------------------------------------------------------------

  parseProgram(): JsNode {
    const program = this.open('program', 0)
    while (!this.atEof()) {
      this.flushComments(program)
      if (this.atEof()) break
      program.add(this.parseStatement())
    }
    this.flushComments(program, this.source.text.length)
    return this.close(program, this.source.text.length)
  }

  private semicolon(parent: JsNode): void {
    if (this.eat(';', parent)) return
    // Automatic semicolon insertion, restricted to the three legal cases. Any
    // other continuation is a parse we do not understand — fail closed.
    if (this.token.kind === 'eof' || this.is('}') || this.token.newlineBefore) return
    throw new ParseError(`expected ";" at ${this.token.start}`)
  }

  // ---- statements ----------------------------------------------------------

  private parseStatement(): JsNode {
    this.enter()
    try {
      return this.parseStatementInner()
    } finally {
      this.exit()
    }
  }

  private parseStatementInner(): JsNode {
    if (this.is('{')) return this.parseBlock()
    if (this.is(';')) {
      const node = this.open('empty_statement')
      this.take(node)
      return this.close(node)
    }
    if (this.is('@')) return this.parseDecorated()

    if (this.token.kind === 'identifier') {
      switch (this.token.value) {
        case 'var':
        case 'let':
        case 'const':
          // `let` is only a declaration when a binding follows.
          if (this.token.value !== 'let' || this.letStartsDeclaration()) return this.parseVariableDeclaration()
          break
        case 'function':
          return this.parseFunctionDeclaration(this.open('function_declaration'))
        case 'class':
          return this.parseClass('class_declaration')
        case 'if':
          return this.parseIf()
        case 'for':
          return this.parseFor()
        case 'while':
          return this.parseWhile()
        case 'do':
          return this.parseDoWhile()
        case 'try':
          return this.parseTry()
        case 'switch':
          return this.parseSwitch()
        case 'return':
        case 'throw':
          return this.parseReturnLike(this.token.value === 'return' ? 'return_statement' : 'throw_statement')
        case 'break':
        case 'continue':
          return this.parseBreakLike(this.token.value === 'break' ? 'break_statement' : 'continue_statement')
        case 'debugger': {
          const node = this.open('debugger_statement')
          this.take(node)
          this.semicolon(node)
          return this.close(node)
        }
        case 'import':
          if (!this.importIsExpression()) return this.parseImport()
          break
        case 'export':
          return this.parseExport()
        case 'async':
          if (this.asyncStartsFunction()) {
            const node = this.open('function_declaration')
            this.take(node)
            return this.parseFunctionDeclaration(node)
          }
          break
        default:
          break
      }
      const typeDecl = this.tryParseTypeDeclaration()
      if (typeDecl) return typeDecl
      if (this.isLabel()) return this.parseLabeled()
    }

    const node = this.open('expression_statement')
    node.add(this.parseExpression())
    this.semicolon(node)
    return this.close(node)
  }

  private parseDecorated(): JsNode {
    // Decorators bind to the following class or member; keep them as siblings of
    // the declaration so statement shape (and therefore rule anchors) is stable.
    const node = this.open('decorator')
    this.take(node)
    node.add(this.parseLeftHandSide(this.parsePrimary()))
    this.close(node)
    const statement = this.parseStatement()
    const wrapper = this.open('decorated_statement', node.startIndex)
    wrapper.add(node)
    wrapper.add(statement)
    return this.close(wrapper)
  }

  private letStartsDeclaration(): boolean {
    const state = this.save()
    this.advance()
    const ok =
      this.token.kind === 'identifier' ||
      this.is('[') ||
      this.is('{')
    this.restore(state)
    return ok
  }

  private importIsExpression(): boolean {
    const state = this.save()
    this.advance()
    const ok = this.is('(') || this.is('.')
    this.restore(state)
    return ok
  }

  private asyncStartsFunction(): boolean {
    const state = this.save()
    this.advance()
    const ok = this.isWord('function') && !this.token.newlineBefore
    this.restore(state)
    return ok
  }

  private isLabel(): boolean {
    if (RESERVED_WORDS.has(this.token.value)) return false
    const state = this.save()
    this.advance()
    const ok = this.is(':')
    this.restore(state)
    return ok
  }

  private parseLabeled(): JsNode {
    const node = this.open('labeled_statement')
    const label = this.open('statement_identifier')
    this.advance()
    node.add(this.close(label, this.prevEnd), 'label')
    this.expect(':', node)
    node.add(this.parseStatement(), 'body')
    return this.close(node)
  }

  private parseBlock(): JsNode {
    const node = this.open('statement_block')
    this.expect('{', node)
    while (!this.is('}')) {
      this.flushComments(node)
      if (this.is('}')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated block')
      node.add(this.parseStatement())
    }
    this.flushComments(node)
    this.expect('}', node)
    return this.close(node)
  }

  private parseVariableDeclaration(): JsNode {
    const kind = this.token.value
    const node = this.open(kind === 'var' ? 'variable_declaration' : 'lexical_declaration')
    this.take(node)
    for (;;) {
      node.add(this.parseVariableDeclarator())
      if (!this.eat(',', node)) break
    }
    this.semicolon(node)
    return this.close(node)
  }

  private parseVariableDeclarator(): JsNode {
    const node = this.open('variable_declarator')
    node.add(this.parseBindingTarget(), 'name')
    this.eat('!', node)
    this.parseOptionalTypeAnnotation(node)
    if (this.eat('=', node)) node.add(this.parseAssignment(), 'value')
    return this.close(node)
  }

  private parseIf(): JsNode {
    const node = this.open('if_statement')
    this.take(node)
    node.add(this.parseParenthesized(), 'condition')
    node.add(this.parseStatement(), 'consequence')
    if (this.isWord('else')) {
      this.take(node)
      node.add(this.parseStatement(), 'alternative')
    }
    return this.close(node)
  }

  private parseParenthesized(): JsNode {
    const node = this.open('parenthesized_expression')
    this.expect('(', node)
    node.add(this.parseExpression())
    this.expect(')', node)
    return this.close(node)
  }

  private parseWhile(): JsNode {
    const node = this.open('while_statement')
    this.take(node)
    node.add(this.parseParenthesized(), 'condition')
    node.add(this.parseStatement(), 'body')
    return this.close(node)
  }

  private parseDoWhile(): JsNode {
    const node = this.open('do_statement')
    this.take(node)
    node.add(this.parseStatement(), 'body')
    this.expectWord('while', node)
    node.add(this.parseParenthesized(), 'condition')
    this.eat(';', node)
    return this.close(node)
  }

  private parseFor(): JsNode {
    const start = this.token.start
    const head = this.open('for_statement', start)
    this.take(head) // for
    const isAwait = this.eatWord('await', head)
    this.expect('(', head)

    // Distinguish `for (x of y)` / `for (x in y)` from the three-clause form by
    // scanning the head; `in` inside the initializer of a C-style for is only
    // reachable through parentheses, which the scan tracks.
    const kind = this.scanForKind()
    if (kind === 'in' || kind === 'of') {
      const node = this.open('for_in_statement', start)
      for (const child of head.children) node.add(child)
      if (this.isWord('var') || this.isWord('const') || (this.isWord('let') && this.letStartsDeclaration())) {
        this.take(node)
      }
      node.add(this.parseBindingTarget(), 'left')
      if (!this.isWord('in') && !this.isWord('of')) throw new ParseError(`expected in/of at ${this.token.start}`)
      this.take(node, 'operator')
      node.add(kind === 'of' ? this.parseAssignment() : this.parseExpression(), 'right')
      this.expect(')', node)
      node.add(this.parseStatement(), 'body')
      return this.close(node)
    }
    if (isAwait) throw new ParseError('for await requires of')

    if (!this.is(';')) {
      if (this.isWord('var') || this.isWord('const') || (this.isWord('let') && this.letStartsDeclaration())) {
        const decl = this.open(this.token.value === 'var' ? 'variable_declaration' : 'lexical_declaration')
        this.take(decl)
        for (;;) {
          decl.add(this.parseVariableDeclarator())
          if (!this.eat(',', decl)) break
        }
        head.add(this.close(decl), 'initializer')
      } else {
        head.add(this.parseExpression(), 'initializer')
      }
    }
    this.expect(';', head)
    if (!this.is(';')) head.add(this.parseExpression(), 'condition')
    this.expect(';', head)
    if (!this.is(')')) head.add(this.parseExpression(), 'increment')
    this.expect(')', head)
    head.add(this.parseStatement(), 'body')
    return this.close(head)
  }

  /** Look ahead over a `for` head to classify it, without consuming anything. */
  private scanForKind(): 'in' | 'of' | 'classic' {
    const state = this.save()
    let depth = 0
    try {
      for (let i = 0; i < 5000; i++) {
        if (this.token.kind === 'eof') break
        if (this.is('(') || this.is('[') || this.is('{')) depth++
        else if (this.is(')') || this.is(']') || this.is('}')) {
          if (depth === 0) break
          depth--
        } else if (depth === 0) {
          if (this.is(';')) return 'classic'
          if (this.isWord('of')) return 'of'
          if (this.isWord('in')) return 'in'
        }
        this.advance()
      }
      return 'classic'
    } finally {
      this.restore(state)
    }
  }

  private parseTry(): JsNode {
    const node = this.open('try_statement')
    this.take(node)
    node.add(this.parseBlock(), 'body')
    if (this.isWord('catch')) {
      const clause = this.open('catch_clause')
      this.take(clause)
      if (this.is('(')) {
        this.expect('(', clause)
        clause.add(this.parseBindingTarget(), 'parameter')
        this.parseOptionalTypeAnnotation(clause)
        this.expect(')', clause)
      }
      clause.add(this.parseBlock(), 'body')
      node.add(this.close(clause), 'handler')
    }
    if (this.isWord('finally')) {
      const clause = this.open('finally_clause')
      this.take(clause)
      clause.add(this.parseBlock(), 'body')
      node.add(this.close(clause), 'finalizer')
    }
    return this.close(node)
  }

  private parseSwitch(): JsNode {
    const node = this.open('switch_statement')
    this.take(node)
    node.add(this.parseParenthesized(), 'value')
    const body = this.open('switch_body')
    this.expect('{', body)
    while (!this.is('}')) {
      this.flushComments(body)
      if (this.is('}')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated switch')
      if (this.isWord('case')) {
        const clause = this.open('switch_case')
        this.take(clause)
        clause.add(this.parseExpression(), 'value')
        this.expect(':', clause)
        this.parseCaseBody(clause)
        body.add(this.close(clause))
      } else if (this.isWord('default')) {
        const clause = this.open('switch_default')
        this.take(clause)
        this.expect(':', clause)
        this.parseCaseBody(clause)
        body.add(this.close(clause))
      } else {
        throw new ParseError(`expected case/default at ${this.token.start}`)
      }
    }
    this.flushComments(body)
    this.expect('}', body)
    node.add(this.close(body), 'body')
    return this.close(node)
  }

  private parseCaseBody(clause: JsNode): void {
    while (!this.is('}') && !this.isWord('case') && !this.isWord('default')) {
      this.flushComments(clause)
      if (this.is('}') || this.isWord('case') || this.isWord('default')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated switch case')
      clause.add(this.parseStatement(), 'body')
    }
  }

  private parseReturnLike(type: string): JsNode {
    const node = this.open(type)
    this.take(node)
    if (!this.is(';') && !this.is('}') && this.token.kind !== 'eof' && !this.token.newlineBefore) {
      node.add(this.parseExpression())
    }
    this.semicolon(node)
    return this.close(node)
  }

  private parseBreakLike(type: string): JsNode {
    const node = this.open(type)
    this.take(node)
    if (this.token.kind === 'identifier' && !this.token.newlineBefore && !this.is(';')) {
      const label = this.open('statement_identifier')
      this.advance()
      node.add(this.close(label, this.prevEnd), 'label')
    }
    this.semicolon(node)
    return this.close(node)
  }

  // ---- modules -------------------------------------------------------------

  private parseImport(): JsNode {
    const node = this.open('import_statement')
    this.take(node)
    this.skipBalancedUntilStatementEnd(node)
    return this.close(node)
  }

  private parseExport(): JsNode {
    const node = this.open('export_statement')
    this.take(node)
    // `export = X` — the CommonJS-interop form in TypeScript declarations.
    if (this.is('=')) {
      this.skipBalancedUntilStatementEnd(node)
      return this.close(node)
    }
    if (this.eatWord('default', node)) {
      if (this.isWord('function') || this.isWord('class') || this.asyncStartsFunction()) {
        node.add(this.parseStatement(), 'declaration')
      } else {
        node.add(this.parseAssignment(), 'value')
        this.semicolon(node)
      }
      return this.close(node)
    }
    if (this.is('{') || this.is('*')) {
      this.skipBalancedUntilStatementEnd(node)
      return this.close(node)
    }
    // `export type { A } from '…'` is a re-export clause, not a type alias.
    if (this.isWord('type') && this.typeReexportAhead()) {
      this.take(node)
      this.skipBalancedUntilStatementEnd(node)
      return this.close(node)
    }
    if (this.isWord('type') || this.isWord('interface') || this.isWord('enum') || this.isWord('declare')) {
      const decl = this.tryParseTypeDeclaration()
      if (decl) {
        node.add(decl, 'declaration')
        return this.close(node)
      }
    }
    node.add(this.parseStatement(), 'declaration')
    return this.close(node)
  }

  private typeReexportAhead(): boolean {
    const state = this.save()
    this.advance()
    const ahead = this.is('{') || this.is('*')
    this.restore(state)
    return ahead
  }

  /** Consume the remainder of an import/export clause (never contains code). */
  private skipBalancedUntilStatementEnd(node: JsNode): void {
    let depth = 0
    for (let i = 0; i < 20_000; i++) {
      if (this.token.kind === 'eof') return
      if (depth === 0 && this.is(';')) {
        this.take(node)
        return
      }
      if (depth === 0 && this.token.newlineBefore && i > 0) return
      if (this.is('{') || this.is('(') || this.is('[')) depth++
      else if (this.is('}') || this.is(')') || this.is(']')) {
        if (depth === 0) return
        depth--
      }
      this.take(node)
    }
    throw new ParseError('module clause too long')
  }

  // ---- TypeScript declarations --------------------------------------------

  /** `interface` / `type` / `enum` / `namespace` / `declare` / `abstract class`. */
  private tryParseTypeDeclaration(): JsNode | null {
    if (this.dialect === 'javascript') return null
    const word = this.token.value
    if (word === 'abstract') {
      const state = this.save()
      this.advance()
      if (this.isWord('class')) {
        this.restore(state)
        const node = this.open('abstract_class_declaration')
        this.take(node)
        return this.parseClassInto(node)
      }
      this.restore(state)
      return null
    }
    if (word === 'declare') {
      const state = this.save()
      this.advance()
      const followsDeclaration = this.token.kind === 'identifier' && !this.token.newlineBefore
      this.restore(state)
      if (!followsDeclaration) return null
      const node = this.open('ambient_declaration')
      this.take(node)
      this.skipDeclarationBody(node)
      return this.close(node)
    }
    if (word === 'interface' || word === 'enum') {
      const state = this.save()
      this.advance()
      if (this.token.kind !== 'identifier') {
        this.restore(state)
        return null
      }
      this.restore(state)
      const node = this.open(word === 'interface' ? 'interface_declaration' : 'enum_declaration')
      this.take(node)
      this.skipDeclarationBody(node, true)
      return this.close(node)
    }
    if (word === 'type') {
      const state = this.save()
      this.advance()
      if (this.token.kind !== 'identifier' || this.token.newlineBefore) {
        this.restore(state)
        return null
      }
      this.advance()
      const isAlias = this.is('=') || this.is('<')
      this.restore(state)
      if (!isAlias) return null
      const node = this.open('type_alias_declaration')
      this.take(node) // type
      node.add(this.parseIdentifier('type_identifier'), 'name')
      this.parseOptionalTypeParameters(node)
      this.expect('=', node)
      this.skipTypeExpression(node, false)
      this.eat(';', node)
      return this.close(node)
    }
    if (word === 'namespace' || word === 'module') {
      const state = this.save()
      this.advance()
      const named = this.token.kind === 'identifier' || this.token.kind === 'string'
      this.restore(state)
      if (!named) return null
      const node = this.open('internal_module')
      this.take(node)
      while (!this.is('{') && this.token.kind !== 'eof') this.take(node)
      node.add(this.parseBlock(), 'body')
      return this.close(node)
    }
    return null
  }

  /**
   * Consume a declaration whose body carries no executable code
   * (`interface`, `enum`, `declare …`).
   *
   * The header before the brace can itself nest brackets — `interface A extends
   * B<{ x: 1 }>` — so brace counting alone stops in the wrong place. This finds
   * the block by scanning the header with full bracket tracking, then consumes
   * exactly one balanced `{ … }`. A declaration with no block (`declare const x:
   * T`) ends at its semicolon or line break.
   */
  private skipDeclarationBody(node: JsNode, requireBlock = false): void {
    let depth = 0
    let angle = 0
    let sawBlock = false
    for (let i = 0; i < 200_000; i++) {
      if (this.atEof()) return
      if (this.is('{')) {
        depth++
        // A brace inside `<…>` belongs to a type argument
        // (`ApiFromModules<{ … }>`), not to the declaration's own block.
        if (angle === 0 && depth === 1) sawBlock = true
      } else if (this.is('(') || this.is('[')) depth++
      else if (this.is('}') || this.is(')') || this.is(']')) {
        depth--
        if (depth < 0) return
        this.take(node)
        if (depth === 0 && angle === 0 && sawBlock) return
        continue
      } else if (this.is('<')) angle++
      else if (angle > 0 && /^>+=?$/.test(this.token.value)) {
        angle -= (this.token.value.match(/>/g) ?? []).length
        if (angle < 0) angle = 0
      } else if (depth === 0 && angle === 0 && !sawBlock) {
        if (this.is(';')) {
          this.take(node)
          return
        }
        // `interface`/`enum` always end in a block, so a line break inside the
        // header (`interface X\n  extends Y`) is not the end of the declaration.
        if (!requireBlock && this.token.newlineBefore && i > 0) return
      }
      if (this.atTemplate()) {
        this.skipTemplateRaw(node)
        continue
      }
      this.take(node)
    }
    throw new ParseError('declaration too long')
  }

  // ---- functions & classes -------------------------------------------------

  private parseFunctionDeclaration(node: JsNode): JsNode {
    this.expectWord('function', node)
    if (this.eat('*', node)) {
      // generator_function_declaration is a distinct grammar node.
      const generator = this.make('generator_function_declaration', node.startIndex, node.endIndex)
      for (const child of node.children) generator.add(child)
      node = generator
    }
    if (this.token.kind === 'identifier') node.add(this.parseIdentifier('identifier'), 'name')
    this.parseOptionalTypeParameters(node)
    node.add(this.parseFormalParameters(), 'parameters')
    this.parseOptionalTypeAnnotation(node)
    if (this.is('{')) node.add(this.parseBlock(), 'body')
    else this.semicolon(node) // TypeScript overload signature
    return this.close(node)
  }

  private parseClass(type: string): JsNode {
    return this.parseClassInto(this.open(type))
  }

  private parseClassInto(node: JsNode): JsNode {
    this.expectWord('class', node)
    if (this.token.kind === 'identifier' && !this.isWord('extends') && !this.isWord('implements')) {
      node.add(this.parseIdentifier('type_identifier'), 'name')
    }
    this.parseOptionalTypeParameters(node)
    while (this.isWord('extends') || this.isWord('implements')) {
      const heritage = this.open('class_heritage')
      this.take(heritage)
      for (;;) {
        heritage.add(this.parseLeftHandSide(this.parsePrimary()))
        // `implements Promise<T>` — type arguments here are never call generics,
        // so they are consumed unconditionally.
        if (this.is('<') && this.dialect !== 'javascript') {
          const typeArguments = this.open('type_arguments')
          this.skipAngleBracketed(typeArguments)
          heritage.add(this.close(typeArguments))
        }
        if (!this.eat(',', heritage)) break
      }
      node.add(this.close(heritage))
    }
    node.add(this.parseClassBody(), 'body')
    return this.close(node)
  }

  private parseClassBody(): JsNode {
    const body = this.open('class_body')
    this.expect('{', body)
    while (!this.is('}')) {
      this.flushComments(body)
      if (this.is('}')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated class body')
      if (this.eat(';', body)) continue
      body.add(this.parseClassMember())
    }
    this.flushComments(body)
    this.expect('}', body)
    return this.close(body)
  }

  private parseClassMember(): JsNode {
    const start = this.token.start
    const scratch = this.open('class_member', start)
    while (this.is('@')) {
      const decorator = this.open('decorator')
      this.take(decorator)
      decorator.add(this.parseLeftHandSide(this.parsePrimary()))
      scratch.add(this.close(decorator))
    }
    // Modifiers are only modifiers when another member token follows; `static`
    // and friends are also legal member names.
    for (let i = 0; i < 8; i++) {
      if (this.token.kind !== 'identifier' || !MODIFIER_KEYWORDS.has(this.token.value)) break
      const state = this.save()
      this.advance()
      const isModifier = !this.is('(') && !this.is('=') && !this.is(';') && !this.is(':') && !this.is('?') && !this.is('<') && !this.is('}')
      this.restore(state)
      if (!isModifier) break
      this.take(scratch)
    }
    // `static { … }` — a class static initialization block.
    if (this.is('{')) {
      const block = this.open('class_static_block', start)
      for (const child of scratch.children) block.add(child)
      block.add(this.parseBlock(), 'body')
      return this.close(block)
    }
    if (this.is('[') && this.indexSignatureAhead()) {
      const signature = this.open('index_signature', start)
      for (const child of scratch.children) signature.add(child)
      this.skipDeclarationBody(signature)
      return this.close(signature)
    }

    let isAsync = false
    let isGenerator = false
    let accessor: 'get' | 'set' | null = null
    if (this.isWord('async')) {
      const state = this.save()
      this.advance()
      if (!this.is('(') && !this.is('=') && !this.is(';') && !this.is(':') && !this.token.newlineBefore) {
        this.restore(state)
        this.take(scratch)
        isAsync = true
      } else this.restore(state)
    }
    if (this.is('*')) {
      this.take(scratch)
      isGenerator = true
    }
    if (this.isWord('get') || this.isWord('set')) {
      const word = this.token.value as 'get' | 'set'
      const state = this.save()
      this.advance()
      if (!this.is('(') && !this.is('=') && !this.is(';') && !this.is(':') && !this.is('}')) {
        this.restore(state)
        this.take(scratch)
        accessor = word
      } else this.restore(state)
    }
    void isAsync
    void isGenerator
    void accessor

    const name = this.parsePropertyName()
    const optional = this.is('?') || this.is('!')
    if (optional) this.take(scratch)

    if (this.is('(') || this.is('<')) {
      const method = this.open('method_definition', start)
      for (const child of scratch.children) method.add(child)
      method.add(name, 'name')
      this.parseOptionalTypeParameters(method)
      method.add(this.parseFormalParameters(), 'parameters')
      this.parseOptionalTypeAnnotation(method)
      if (this.is('{')) method.add(this.parseBlock(), 'body')
      else this.semicolon(method)
      return this.close(method)
    }

    const field = this.open('field_definition', start)
    for (const child of scratch.children) field.add(child)
    field.add(name, 'property')
    this.parseOptionalTypeAnnotation(field)
    if (this.eat('=', field)) field.add(this.parseAssignment(), 'value')
    this.semicolon(field)
    return this.close(field)
  }

  private indexSignatureAhead(): boolean {
    if (this.dialect === 'javascript') return false
    const state = this.save()
    try {
      this.advance()
      if (this.token.kind !== 'identifier') return false
      this.advance()
      return this.is(':')
    } finally {
      this.restore(state)
    }
  }

  private parsePropertyName(): JsNode {
    if (this.is('[')) {
      const node = this.open('computed_property_name')
      this.take(node)
      node.add(this.parseAssignment())
      this.expect(']', node)
      return this.close(node)
    }
    if (this.token.kind === 'string') return this.parseStringLiteral()
    if (this.token.kind === 'number') {
      const node = this.open('number')
      this.advance()
      return this.close(node, this.prevEnd)
    }
    if (this.token.kind === 'private') {
      const node = this.open('private_property_identifier')
      this.advance()
      return this.close(node, this.prevEnd)
    }
    if (this.token.kind !== 'identifier') throw new ParseError(`expected property name at ${this.token.start}`)
    return this.parseIdentifier('property_identifier')
  }

  private parseIdentifier(type: string): JsNode {
    if (this.token.kind !== 'identifier') throw new ParseError(`expected identifier at ${this.token.start}`)
    const node = this.open(type)
    this.advance()
    return this.close(node, this.prevEnd)
  }

  private parseFormalParameters(): JsNode {
    const node = this.open('formal_parameters')
    this.expect('(', node)
    while (!this.is(')')) {
      this.flushComments(node)
      if (this.is(')')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated parameter list')
      node.add(this.parseParameter())
      if (!this.eat(',', node)) break
    }
    this.flushComments(node)
    this.expect(')', node)
    return this.close(node)
  }

  /**
   * One parameter. TypeScript files wrap the binding in
   * `required_parameter`/`optional_parameter` with `pattern` and `type` fields —
   * exactly what `open-record-write` reads to see an `any`/`Record<string,
   * unknown>` annotation. Plain JavaScript has no annotations, so the binding
   * pattern stands alone, matching tree-sitter-javascript.
   */
  private parseParameter(): JsNode {
    const start = this.token.start
    const scratch = this.open('parameter', start)
    while (this.is('@')) {
      const decorator = this.open('decorator')
      this.take(decorator)
      decorator.add(this.parseLeftHandSide(this.parsePrimary()))
      scratch.add(this.close(decorator))
    }
    let hasModifier = false
    for (let i = 0; i < 4; i++) {
      if (this.token.kind !== 'identifier' || !MODIFIER_KEYWORDS.has(this.token.value)) break
      const state = this.save()
      this.advance()
      const isModifier = this.token.kind === 'identifier' || this.is('{') || this.is('[') || this.is('...')
      this.restore(state)
      if (!isModifier) break
      this.take(scratch)
      hasModifier = true
    }

    const rest = this.is('...')
    const pattern = this.parseBindingTarget()
    const optional = this.is('?')
    const typed = optional || this.is(':')
    if (optional) this.take(scratch)

    if (this.dialect === 'javascript' || (!typed && !hasModifier && scratch.children.length === 0)) {
      // Plain binding: default values become assignment_pattern, matching
      // tree-sitter-javascript's `formal_parameters` children.
      if (this.is('=')) {
        const node = this.open('assignment_pattern', start)
        node.add(pattern, 'left')
        this.expect('=', node)
        node.add(this.parseAssignment(), 'right')
        return this.close(node)
      }
      return pattern
    }

    const node = this.open(optional ? 'optional_parameter' : 'required_parameter', start)
    for (const child of scratch.children) node.add(child)
    node.add(pattern, 'pattern')
    void rest
    this.parseOptionalTypeAnnotation(node)
    if (this.eat('=', node)) node.add(this.parseAssignment(), 'value')
    return this.close(node)
  }

  /** A binding target: identifier, object/array pattern, or rest. */
  private parseBindingTarget(): JsNode {
    if (this.is('...')) {
      const node = this.open('rest_pattern')
      this.take(node)
      node.add(this.parseBindingTarget())
      return this.close(node)
    }
    if (this.is('{')) return this.parseObjectPattern()
    if (this.is('[')) return this.parseArrayPattern()
    if (this.isWord('this')) {
      const node = this.open('this')
      this.advance()
      return this.parseBindingSuffixes(this.close(node, this.prevEnd))
    }
    return this.parseBindingSuffixes(this.parseIdentifier('identifier'))
  }

  /**
   * Member and index suffixes on a binding target.
   *
   * Destructuring assignment targets are not restricted to plain names —
   * `[node.leadingComments, last] = f()` is ordinary code — so a target may be a
   * member chain. Declarations never produce one (`.`/`[` cannot follow a
   * declared name), so this costs nothing where it does not apply.
   */
  private parseBindingSuffixes(target: JsNode): JsNode {
    let expression = target
    for (let i = 0; i < 64; i++) {
      if (this.is('.')) {
        const node = this.open('member_expression', expression.startIndex)
        node.add(expression, 'object')
        this.take(node)
        node.add(this.parseIdentifier('property_identifier'), 'property')
        expression = this.close(node)
        continue
      }
      if (this.is('[')) {
        const node = this.open('subscript_expression', expression.startIndex)
        node.add(expression, 'object')
        this.take(node)
        node.add(this.parseExpression(), 'index')
        this.expect(']', node)
        expression = this.close(node)
        continue
      }
      break
    }
    return expression
  }

  private parseObjectPattern(): JsNode {
    const node = this.open('object_pattern')
    this.expect('{', node)
    while (!this.is('}')) {
      this.flushComments(node)
      if (this.is('}')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated object pattern')
      node.add(this.parseObjectPatternProperty())
      if (!this.eat(',', node)) break
    }
    this.flushComments(node)
    this.expect('}', node)
    return this.close(node)
  }

  private parseObjectPatternProperty(): JsNode {
    if (this.is('...')) {
      const node = this.open('rest_pattern')
      this.take(node)
      node.add(this.parseBindingTarget())
      return this.close(node)
    }
    const start = this.token.start
    const computed = this.is('[')
    const key = this.parsePropertyName()
    if (this.is(':')) {
      const node = this.open('pair_pattern', start)
      node.add(key, 'key')
      this.expect(':', node)
      node.add(this.parseBindingTargetWithDefault(), 'value')
      return this.close(node)
    }
    if (computed) throw new ParseError('computed key requires a binding')
    // `{ a }` / `{ a = 1 }` — the shorthand forms.
    const shorthand = this.make('shorthand_property_identifier_pattern', key.startIndex, key.endIndex)
    if (this.is('=')) {
      const node = this.open('object_assignment_pattern', start)
      node.add(shorthand, 'left')
      this.expect('=', node)
      node.add(this.parseAssignment(), 'right')
      return this.close(node)
    }
    return shorthand
  }

  private parseBindingTargetWithDefault(): JsNode {
    const start = this.token.start
    const target = this.parseBindingTarget()
    if (!this.is('=')) return target
    const node = this.open('assignment_pattern', start)
    node.add(target, 'left')
    this.expect('=', node)
    node.add(this.parseAssignment(), 'right')
    return this.close(node)
  }

  private parseArrayPattern(): JsNode {
    const node = this.open('array_pattern')
    this.expect('[', node)
    while (!this.is(']')) {
      this.flushComments(node)
      if (this.is(']')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated array pattern')
      if (this.is(',')) {
        this.take(node) // elision
        continue
      }
      node.add(this.parseBindingTargetWithDefault())
      if (!this.eat(',', node)) break
    }
    this.flushComments(node)
    this.expect(']', node)
    return this.close(node)
  }

  // ---- TypeScript type syntax ---------------------------------------------

  /** `: T` after a binding, parameter, or signature. Opaque by design. */
  private parseOptionalTypeAnnotation(parent: JsNode, stopAtArrow = false): void {
    if (this.dialect === 'javascript' || !this.is(':')) return
    const node = this.open('type_annotation')
    this.take(node)
    this.skipTypeExpression(node, stopAtArrow)
    parent.add(this.close(node), 'type')
  }

  private parseOptionalTypeParameters(parent: JsNode): void {
    if (this.dialect === 'javascript' || !this.is('<')) return
    const node = this.open('type_parameters')
    this.skipAngleBracketed(node)
    parent.add(this.close(node), 'type_parameters')
  }

  /**
   * Consume a type expression as an opaque span.
   *
   * The rules never inspect a parsed type — `open-record-write` reads
   * `type_annotation.text` and nothing else — so parsing TypeScript's full type
   * grammar would be cost without a consumer. What must be exact is where the
   * type ENDS, which is what this tracks: bracket depth, `?:` conditional-type
   * pairing, and (for arrow return types) the `=>` that starts the body.
   */
  private skipTypeExpression(node: JsNode, stopAtArrow: boolean): void {
    let depth = 0
    let angle = 0
    let conditional = 0
    // A type ends where an operand would start a *new* construct. Tracking
    // "does the syntax so far still demand more type?" is what separates
    // `function f(): Foo {` (body) from `function f(): { a: X } {` (object type),
    // and `let x: Foo` + newline + `bar()` from a continuation. Getting this
    // wrong swallows executable code into a type span, so it is deliberately
    // conservative: when in doubt, stop.
    let expectingType = true
    for (let i = 0; i < 200_000; i++) {
      if (this.token.kind === 'eof') return
      const value = this.token.value
      if (depth === 0 && angle === 0) {
        if (this.is(')') || this.is(']') || this.is(',') || this.is(';')) return
        if (this.is('=') || ASSIGN_OPS.has(value)) return
        if (stopAtArrow && this.is('=>')) return
        if (!expectingType) {
          if (this.is('{') || this.is('(')) return
          if (this.token.kind === 'number' || this.token.kind === 'string' || this.token.kind === 'template_start') return
          if (this.token.kind === 'identifier' && !TYPE_CONTINUATION_WORDS.has(value)) return
        }
        if (this.is('}')) return
        if (this.is('?')) conditional++
        else if (this.is(':')) {
          if (conditional === 0) return
          conditional--
        }
      }
      if (this.is('(') || this.is('[') || this.is('{')) depth++
      else if (this.is(')') || this.is(']') || this.is('}')) depth--
      else if (this.is('<')) angle++
      else if (angle > 0 && /^>+=?$/.test(value)) {
        angle -= (value.match(/>/g) ?? []).length
        if (angle < 0) angle = 0
      }
      if (this.atTemplate()) {
        this.skipTemplateRaw(node)
        expectingType = false
        continue
      }
      expectingType = TYPE_OPERATOR_TOKENS.has(value)
      this.take(node)
    }
    throw new ParseError('type expression too long')
  }

  /**
   * Consume a whole template literal at the character level.
   *
   * Used wherever the surrounding syntax is a TYPE: a template literal *type*
   * (`` `${infer A} ${infer B}` ``) holds type syntax in its substitutions, so
   * parsing them as expressions fails on perfectly valid code. Types have no
   * consumer in the rule pack, so the literal only needs to be spanned, not
   * understood.
   */
  private skipTemplateRaw(node: JsNode): void {
    const text = this.lexer.text
    const start = this.token.start
    type Frame = { kind: 'literal' } | { kind: 'substitution'; depth: number }
    const stack: Frame[] = [{ kind: 'literal' }]
    let i = start + 1
    while (stack.length) {
      if (i >= text.length) throw new ParseError('unterminated template literal')
      const top = stack[stack.length - 1]
      const char = text[i]
      if (char === '\\') {
        i += 2
        continue
      }
      if (top.kind === 'literal') {
        if (char === '`') {
          stack.pop()
          i++
        } else if (char === '$' && text[i + 1] === '{') {
          stack.push({ kind: 'substitution', depth: 0 })
          i += 2
        } else i++
        continue
      }
      if (char === '`') {
        stack.push({ kind: 'literal' })
        i++
      } else if (char === '"' || char === "'") {
        const closing = text.indexOf(char, i + 1)
        if (closing === -1) throw new ParseError('unterminated string in template type')
        i = closing + 1
      } else if (char === '{') {
        top.depth++
        i++
      } else if (char === '}') {
        if (top.depth === 0) stack.pop()
        else top.depth--
        i++
      } else i++
    }
    node.add(this.make('template_string', start, i))
    this.lexer.pos = i
    this.prevEnd = i
    this.token = this.lexer.next(false)
  }

  /** Consume a balanced `<...>` run, tolerating `>>` closing two levels. */
  private skipAngleBracketed(node: JsNode): void {
    let angle = 0
    for (let i = 0; i < 20_000; i++) {
      if (this.token.kind === 'eof') throw new ParseError('unterminated type arguments')
      if (this.is('<')) angle++
      else if (this.is('>') || this.is('>>') || this.is('>>>')) {
        angle -= this.token.value.length
      } else if (this.is('>=') || this.is('>>=') || this.is('>>>=')) {
        angle -= this.token.value.length - 1
      }
      if (this.atTemplate()) {
        this.skipTemplateRaw(node)
        continue
      }
      this.take(node)
      if (angle <= 0) return
    }
    throw new ParseError('type arguments too long')
  }

  // ---- expressions ---------------------------------------------------------

  private parseExpression(): JsNode {
    let expression = this.parseAssignment()
    while (this.is(',')) {
      const node = this.open('sequence_expression', expression.startIndex)
      node.add(expression, 'left')
      this.take(node)
      node.add(this.parseAssignment(), 'right')
      expression = this.close(node)
    }
    return expression
  }

  private parseAssignment(): JsNode {
    this.enter()
    try {
      return this.parseAssignmentInner()
    } finally {
      this.exit()
    }
  }

  private parseAssignmentInner(): JsNode {
    if (this.isWord('yield')) return this.parseYield()
    const arrow = this.tryParseArrowFunction()
    if (arrow) return arrow

    const start = this.token.start

    // A destructuring assignment must be recognized BEFORE its target is
    // parsed: `({ bg = "#fff" } = style)` is not a valid object literal, and
    // reading it as one both fails and would leave `bg` unbound for taint.
    if ((this.is('{') || this.is('[')) && this.destructuringAssignmentAhead()) {
      const node = this.open('assignment_expression', start)
      node.add(this.parseBindingTarget(), 'left')
      this.expect('=', node, 'operator')
      node.add(this.parseAssignment(), 'right')
      return this.close(node)
    }

    const left = this.parseConditional()

    if (this.is('=')) {
      const node = this.open('assignment_expression', start)
      node.add(left, 'left')
      this.take(node, 'operator')
      node.add(this.parseAssignment(), 'right')
      return this.close(node)
    }
    if (this.token.kind === 'punct' && ASSIGN_OPS.has(this.token.value)) {
      const node = this.open('augmented_assignment_expression', start)
      node.add(left, 'left')
      this.take(node, 'operator')
      node.add(this.parseAssignment(), 'right')
      return this.close(node)
    }
    return left
  }

  /** Does a balanced `{…}`/`[…]` starting here close and get assigned to? */
  private destructuringAssignmentAhead(): boolean {
    const state = this.save()
    try {
      let depth = 0
      for (let i = 0; i < 20_000; i++) {
        if (this.atEof()) return false
        if (this.is('{') || this.is('[') || this.is('(')) depth++
        else if (this.is('}') || this.is(']') || this.is(')')) {
          depth--
          if (depth === 0) {
            this.advance()
            return this.is('=')
          }
          if (depth < 0) return false
        } else if (this.atTemplate()) {
          this.skipTemplateRaw(this.open('scratch'))
          continue
        }
        this.advance()
      }
      return false
    } catch {
      return false
    } finally {
      this.restore(state)
    }
  }

  private parseYield(): JsNode {
    const node = this.open('yield_expression')
    this.take(node)
    this.eat('*', node)
    if (!this.is(')') && !this.is(']') && !this.is('}') && !this.is(',') && !this.is(';') && this.token.kind !== 'eof' && !this.token.newlineBefore) {
      node.add(this.parseAssignment())
    }
    return this.close(node)
  }

  private parseConditional(): JsNode {
    const start = this.token.start
    const test = this.parseBinary(0)
    if (!this.is('?')) return test
    const node = this.open('ternary_expression', start)
    node.add(test, 'condition')
    this.take(node)
    node.add(this.parseAssignment(), 'consequence')
    this.expect(':', node)
    node.add(this.parseAssignment(), 'alternative')
    return this.close(node)
  }

  private parseBinary(minPrecedence: number): JsNode {
    let left = this.parseUnary()
    for (;;) {
      // `as` / `satisfies` bind like a postfix operator on the left operand.
      if (this.dialect !== 'javascript' && (this.isWord('as') || this.isWord('satisfies')) && !this.token.newlineBefore) {
        const node = this.open(this.token.value === 'as' ? 'as_expression' : 'satisfies_expression', left.startIndex)
        node.add(left)
        this.take(node)
        // Not stopAtArrow: `x as (c: T) => U` is a function TYPE, and cutting it
        // at the `=>` would leave the return type as loose expression tokens.
        if (this.isWord('const')) this.take(node)
        else this.skipTypeExpression(node, false)
        left = this.close(node)
        continue
      }
      const operator = this.token.kind === 'identifier' ? this.token.value : this.token.kind === 'punct' ? this.token.value : null
      if (!operator) break
      if (operator === 'in' || operator === 'instanceof') {
        if (this.token.kind !== 'identifier') break
      } else if (this.token.kind !== 'punct') break
      const precedence = BINARY_PRECEDENCE[operator]
      if (precedence === undefined || precedence <= minPrecedence) break
      const node = this.open('binary_expression', left.startIndex)
      node.add(left, 'left')
      this.take(node, 'operator')
      // `**` is right-associative; everything else is left-associative.
      node.add(this.parseBinary(operator === '**' ? precedence - 1 : precedence), 'right')
      left = this.close(node)
    }
    return left
  }

  private parseUnary(): JsNode {
    const start = this.token.start
    if (this.token.kind === 'punct' && (this.token.value === '!' || this.token.value === '~' || this.token.value === '+' || this.token.value === '-')) {
      const node = this.open('unary_expression', start)
      this.take(node, 'operator')
      node.add(this.parseUnary(), 'argument')
      return this.close(node)
    }
    if (this.token.kind === 'identifier' && (this.token.value === 'typeof' || this.token.value === 'void' || this.token.value === 'delete')) {
      const node = this.open('unary_expression', start)
      this.take(node, 'operator')
      node.add(this.parseUnary(), 'argument')
      return this.close(node)
    }
    if (this.isWord('await')) {
      const state = this.save()
      this.advance()
      // `await` is a plain identifier outside async code; only treat it as an
      // operator when an operand actually follows.
      if (this.startsExpression()) {
        const node = this.open('await_expression', start)
        this.restore(state)
        this.take(node)
        node.add(this.parseUnary())
        return this.close(node)
      }
      this.restore(state)
    }
    if (this.is('++') || this.is('--')) {
      const node = this.open('update_expression', start)
      this.take(node, 'operator')
      node.add(this.parseUnary(), 'argument')
      return this.close(node)
    }
    if (this.dialect === 'typescript' && this.is('<')) {
      const node = this.open('type_assertion', start)
      this.skipAngleBracketed(node)
      node.add(this.parseUnary())
      return this.close(node)
    }
    let expression = this.parseLeftHandSide(this.parsePrimary())
    if ((this.is('++') || this.is('--')) && !this.token.newlineBefore) {
      const node = this.open('update_expression', start)
      node.add(expression, 'argument')
      this.take(node, 'operator')
      expression = this.close(node)
    }
    return expression
  }

  private startsExpression(): boolean {
    switch (this.token.kind) {
      case 'identifier':
        return !['in', 'instanceof', 'as', 'satisfies', 'of'].includes(this.token.value)
      case 'number':
      case 'string':
      case 'regex':
      case 'template_start':
      case 'private':
        return true
      case 'punct':
        return ['(', '[', '{', '!', '~', '+', '-', '++', '--', '...', '<'].includes(this.token.value)
      default:
        return false
    }
  }

  /** Member/subscript/call chains, including optional chaining and templates. */
  private parseLeftHandSide(base: JsNode): JsNode {
    let expression = base
    for (let i = 0; i < 10_000; i++) {
      if (this.is('.') || this.is('?.')) {
        const optional = this.is('?.')
        const node = this.open('member_expression', expression.startIndex)
        node.add(expression, 'object')
        this.take(node)
        if (optional && this.is('(')) {
          // `a?.()` — an optional CALL, not a member access.
          const call = this.open('call_expression', expression.startIndex)
          for (const child of node.children) call.add(child)
          call.setField('function', expression)
          call.add(this.parseArguments(), 'arguments')
          expression = this.close(call)
          continue
        }
        if (optional && this.is('[')) {
          const subscript = this.open('subscript_expression', expression.startIndex)
          for (const child of node.children) subscript.add(child)
          subscript.setField('object', expression)
          this.expect('[', subscript)
          subscript.add(this.parseExpression(), 'index')
          this.expect(']', subscript)
          expression = this.close(subscript)
          continue
        }
        node.add(
          this.token.kind === 'private' ? this.parsePrivateName() : this.parseIdentifier('property_identifier'),
          'property',
        )
        expression = this.close(node)
        continue
      }
      if (this.is('[')) {
        const node = this.open('subscript_expression', expression.startIndex)
        node.add(expression, 'object')
        this.take(node)
        node.add(this.parseExpression(), 'index')
        this.expect(']', node)
        expression = this.close(node)
        continue
      }
      if (this.is('(')) {
        const node = this.open('call_expression', expression.startIndex)
        node.add(expression, 'function')
        node.add(this.parseArguments(), 'arguments')
        expression = this.close(node)
        continue
      }
      if (this.atTemplate()) {
        // Tagged template: tree-sitter models it as a call whose `arguments`
        // field IS the template_string.
        const node = this.open('call_expression', expression.startIndex)
        node.add(expression, 'function')
        node.add(this.parseTemplateString(), 'arguments')
        expression = this.close(node)
        continue
      }
      if (this.is('!') && !this.token.newlineBefore && this.dialect !== 'javascript') {
        const node = this.open('non_null_expression', expression.startIndex)
        node.add(expression)
        this.take(node)
        expression = this.close(node)
        continue
      }
      if (this.is('<') && this.dialect !== 'javascript') {
        const typeArguments = this.tryParseTypeArguments()
        if (!typeArguments) break
        if (this.is('(')) {
          const node = this.open('call_expression', expression.startIndex)
          node.add(expression, 'function')
          node.add(typeArguments, 'type_arguments')
          node.add(this.parseArguments(), 'arguments')
          expression = this.close(node)
          continue
        }
        if (this.atTemplate()) {
          const node = this.open('call_expression', expression.startIndex)
          node.add(expression, 'function')
          node.add(typeArguments, 'type_arguments')
          node.add(this.parseTemplateString(), 'arguments')
          expression = this.close(node)
          continue
        }
        break
      }
      break
    }
    return expression
  }

  private parsePrivateName(): JsNode {
    const node = this.open('private_property_identifier')
    this.advance()
    return this.close(node, this.prevEnd)
  }

  /**
   * `f<T>(x)` vs `f < T > (x)`. Only accept type arguments when the balanced
   * `<...>` is immediately followed by a call or tagged template — the same
   * disambiguation TypeScript itself applies.
   */
  private tryParseTypeArguments(): JsNode | null {
    const state = this.save()
    try {
      const node = this.open('type_arguments')
      this.skipAngleBracketed(node)
      this.close(node)
      if (this.is('(') || this.atTemplate()) return node
      this.restore(state)
      return null
    } catch {
      this.restore(state)
      return null
    }
  }

  private parseArguments(): JsNode {
    const node = this.open('arguments')
    this.expect('(', node)
    while (!this.is(')')) {
      this.flushComments(node)
      if (this.is(')')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated argument list')
      if (this.is('...')) {
        const spread = this.open('spread_element')
        this.take(spread)
        spread.add(this.parseAssignment())
        node.add(this.close(spread))
      } else {
        node.add(this.parseAssignment())
      }
      if (!this.eat(',', node)) break
    }
    this.flushComments(node)
    this.expect(')', node)
    return this.close(node)
  }

  // ---- arrow functions -----------------------------------------------------

  /**
   * Arrow functions require unbounded lookahead (`(a, b): T => …` vs a
   * parenthesized expression), so this speculatively scans to the matching `)`
   * and commits only when `=>` follows. A failed attempt restores exactly.
   */
  private tryParseArrowFunction(): JsNode | null {
    const start = this.token.start
    const state = this.save()

    let isAsync = false
    if (this.isWord('async')) {
      const probe = this.save()
      this.advance()
      if (this.token.newlineBefore || (!this.is('(') && this.token.kind !== 'identifier' && !this.is('<'))) {
        this.restore(probe)
        return null
      }
      isAsync = true
    }

    if (this.token.kind === 'identifier' && !RESERVED_WORDS.has(this.token.value)) {
      const probe = this.save()
      this.advance()
      if (this.is('=>')) {
        this.restore(probe)
        const node = this.open('arrow_function', start)
        if (isAsync) {
          this.restore(state)
          this.take(node)
        }
        node.add(this.parseIdentifier('identifier'), 'parameter')
        return this.finishArrow(node)
      }
      this.restore(state)
      return null
    }

    if (!this.is('(') && !(this.is('<') && this.dialect !== 'javascript')) {
      this.restore(state)
      return null
    }
    if (!this.arrowFollows()) {
      this.restore(state)
      return null
    }

    const node = this.open('arrow_function', start)
    this.restore(state)
    if (isAsync) this.take(node)
    if (this.is('<')) this.parseOptionalTypeParameters(node)
    node.add(this.parseFormalParameters(), 'parameters')
    this.parseOptionalTypeAnnotation(node, true)
    return this.finishArrow(node)
  }

  /** Scan past a balanced parameter list (and optional return type) for `=>`. */
  private arrowFollows(): boolean {
    const state = this.save()
    try {
      if (this.is('<')) {
        const scratch = this.open('type_parameters')
        this.skipAngleBracketed(scratch)
        if (!this.is('(')) return false
      }
      let depth = 0
      for (let i = 0; i < 20_000; i++) {
        if (this.token.kind === 'eof') return false
        if (this.is('(') || this.is('[') || this.is('{')) depth++
        else if (this.is(')') || this.is(']') || this.is('}')) {
          depth--
          if (depth === 0) {
            this.advance()
            break
          }
          if (depth < 0) return false
        } else if (this.atTemplate()) {
          this.parseTemplateString()
          continue
        }
        this.advance()
      }
      if (this.is('=>')) return true
      if (this.is(':') && this.dialect !== 'javascript') {
        const scratch = this.open('type_annotation')
        this.take(scratch)
        this.skipTypeExpression(scratch, true)
        return this.is('=>')
      }
      return false
    } catch {
      return false
    } finally {
      this.restore(state)
    }
  }

  private finishArrow(node: JsNode): JsNode {
    this.expect('=>', node)
    if (this.is('{')) node.add(this.parseBlock(), 'body')
    else node.add(this.parseAssignment(), 'body')
    return this.close(node)
  }

  // ---- primary expressions -------------------------------------------------

  private parsePrimary(): JsNode {
    const start = this.token.start
    if (this.token.kind === 'punct' && (this.token.value === '/' || this.token.value === '/=')) {
      this.relexAsRegex()
    }

    switch (this.token.kind) {
      case 'number': {
        const node = this.open('number')
        this.advance()
        return this.close(node, this.prevEnd)
      }
      case 'string':
        return this.parseStringLiteral()
      case 'regex': {
        const node = this.open('regex')
        this.advance()
        return this.close(node, this.prevEnd)
      }
      case 'template_start':
        return this.parseTemplateString()
      case 'private': {
        // `#x in obj` — a private-name brand check.
        return this.parsePrivateName()
      }
      case 'identifier':
        return this.parsePrimaryIdentifier()
      case 'punct':
        break
      default:
        throw new ParseError(`unexpected token at ${start}`)
    }

    if (this.is('(')) {
      const node = this.open('parenthesized_expression')
      this.take(node)
      node.add(this.parseExpression())
      this.expect(')', node)
      return this.close(node)
    }
    if (this.is('[')) return this.parseArrayLiteral()
    if (this.is('{')) return this.parseObjectLiteral()
    if (this.is('<') && this.jsx) return this.parseJsx()
    throw new ParseError(`unexpected token ${JSON.stringify(this.token.value)} at ${start}`)
  }

  private parsePrimaryIdentifier(): JsNode {
    const word = this.token.value
    if (KEYWORD_LITERALS.has(word)) {
      const node = this.open(word)
      this.advance()
      return this.close(node, this.prevEnd)
    }
    if (word === 'this' || word === 'super') {
      const node = this.open(word)
      this.advance()
      return this.close(node, this.prevEnd)
    }
    if (word === 'function') return this.parseFunctionExpression(this.open('function_expression'))
    if (word === 'class') return this.parseClass('class')
    if (word === 'new') return this.parseNew()
    if (word === 'import') {
      const node = this.open('import')
      this.advance()
      return this.close(node, this.prevEnd)
    }
    if (word === 'async') {
      const state = this.save()
      this.advance()
      if (this.isWord('function') && !this.token.newlineBefore) {
        this.restore(state)
        const node = this.open('function_expression')
        this.take(node)
        return this.parseFunctionExpression(node)
      }
      this.restore(state)
    }
    return this.parseIdentifier('identifier')
  }

  private parseFunctionExpression(node: JsNode): JsNode {
    this.expectWord('function', node)
    if (this.eat('*', node)) {
      const generator = this.make('generator_function', node.startIndex, node.endIndex)
      for (const child of node.children) generator.add(child)
      node = generator
    }
    if (this.token.kind === 'identifier' && !this.is('(')) node.add(this.parseIdentifier('identifier'), 'name')
    this.parseOptionalTypeParameters(node)
    node.add(this.parseFormalParameters(), 'parameters')
    this.parseOptionalTypeAnnotation(node)
    node.add(this.parseBlock(), 'body')
    return this.close(node)
  }

  private parseNew(): JsNode {
    const node = this.open('new_expression')
    this.take(node)
    if (this.is('.')) {
      // new.target
      this.take(node)
      this.parseIdentifier('property_identifier')
      return this.close(node, this.prevEnd)
    }
    let constructor = this.parsePrimary()
    // Member access binds tighter than `new`, but a call terminates it.
    for (let i = 0; i < 1000; i++) {
      if (this.is('.') || this.is('[')) {
        if (this.is('.')) {
          const member = this.open('member_expression', constructor.startIndex)
          member.add(constructor, 'object')
          this.take(member)
          member.add(this.parseIdentifier('property_identifier'), 'property')
          constructor = this.close(member)
        } else {
          const subscript = this.open('subscript_expression', constructor.startIndex)
          subscript.add(constructor, 'object')
          this.take(subscript)
          subscript.add(this.parseExpression(), 'index')
          this.expect(']', subscript)
          constructor = this.close(subscript)
        }
        continue
      }
      break
    }
    node.add(constructor, 'constructor')
    if (this.is('<') && this.dialect !== 'javascript') {
      const typeArguments = this.tryParseTypeArguments()
      if (typeArguments) node.add(typeArguments, 'type_arguments')
    }
    if (this.is('(')) node.add(this.parseArguments(), 'arguments')
    return this.close(node)
  }

  private parseStringLiteral(): JsNode {
    const node = this.open('string')
    const start = this.token.start
    const end = this.token.end
    this.advance()
    // tree-sitter exposes the unquoted body as a `string_fragment` child.
    if (end - start > 2) node.add(this.make('string_fragment', start + 1, end - 1))
    return this.close(node, end)
  }

  private parseTemplateString(): JsNode {
    const node = this.open('template_string')
    if (this.token.kind !== 'template_start') throw new ParseError('expected template literal')
    // The opening backtick is consumed WITHOUT advancing: what follows is raw
    // literal text, and tokenizing it would read `2px` as a bad number.
    node.add(this.make('`', this.token.start, this.token.end, false))
    let cursor = this.token.end
    this.prevEnd = cursor
    for (let i = 0; i < 20_000; i++) {
      const chunk = this.lexer.templateChunk(cursor)
      if (chunk.fragmentEnd > cursor) node.add(this.make('string_fragment', cursor, chunk.fragmentEnd))
      if (chunk.kind === 'end') {
        node.add(this.make('`', chunk.fragmentEnd, chunk.fragmentEnd + 1, false))
        this.lexer.pos = chunk.fragmentEnd + 1
        this.prevEnd = this.lexer.pos
        this.token = this.lexer.next(false)
        return this.close(node, chunk.fragmentEnd + 1)
      }
      const substitution = this.make('template_substitution', chunk.fragmentEnd, chunk.fragmentEnd)
      substitution.add(this.make('${', chunk.fragmentEnd, chunk.fragmentEnd + 2, false))
      this.lexer.pos = chunk.fragmentEnd + 2
      this.token = this.lexer.next(true)
      substitution.add(this.parseExpression())
      if (!this.is('}')) throw new ParseError(`unterminated template substitution at ${this.token.start}`)
      substitution.add(this.make('}', this.token.start, this.token.start + 1, false))
      this.close(substitution, this.token.start + 1)
      node.add(substitution)
      cursor = this.token.start + 1
    }
    throw new ParseError('template literal too long')
  }

  private parseArrayLiteral(): JsNode {
    const node = this.open('array')
    this.expect('[', node)
    while (!this.is(']')) {
      this.flushComments(node)
      if (this.is(']')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated array literal')
      if (this.is(',')) {
        this.take(node) // elision
        continue
      }
      if (this.is('...')) {
        const spread = this.open('spread_element')
        this.take(spread)
        spread.add(this.parseAssignment())
        node.add(this.close(spread))
      } else {
        node.add(this.parseAssignment())
      }
      if (!this.eat(',', node)) break
    }
    this.flushComments(node)
    this.expect(']', node)
    return this.close(node)
  }

  private parseObjectLiteral(): JsNode {
    const node = this.open('object')
    this.expect('{', node)
    while (!this.is('}')) {
      this.flushComments(node)
      if (this.is('}')) break
      if (this.token.kind === 'eof') throw new ParseError('unterminated object literal')
      node.add(this.parseObjectMember())
      if (!this.eat(',', node)) break
    }
    this.flushComments(node)
    this.expect('}', node)
    return this.close(node)
  }

  private parseObjectMember(): JsNode {
    const start = this.token.start
    if (this.is('...')) {
      const node = this.open('spread_element')
      this.take(node)
      node.add(this.parseAssignment())
      return this.close(node)
    }

    const scratch = this.open('object_member', start)
    let sawModifier = false
    if (this.isWord('async')) {
      const state = this.save()
      this.advance()
      if (!this.is(':') && !this.is('(') && !this.is(',') && !this.is('}') && !this.token.newlineBefore) {
        this.restore(state)
        this.take(scratch)
        sawModifier = true
      } else this.restore(state)
    }
    if (this.is('*')) {
      this.take(scratch)
      sawModifier = true
    }
    if (this.isWord('get') || this.isWord('set')) {
      const state = this.save()
      this.advance()
      if (!this.is(':') && !this.is('(') && !this.is(',') && !this.is('}') && !this.is('=')) {
        this.restore(state)
        this.take(scratch)
        sawModifier = true
      } else this.restore(state)
    }

    const key = this.parsePropertyName()
    if (this.is('(') || this.is('<')) {
      const method = this.open('method_definition', start)
      for (const child of scratch.children) method.add(child)
      method.add(key, 'name')
      this.parseOptionalTypeParameters(method)
      method.add(this.parseFormalParameters(), 'parameters')
      this.parseOptionalTypeAnnotation(method)
      method.add(this.parseBlock(), 'body')
      return this.close(method)
    }
    if (sawModifier) throw new ParseError(`expected method body at ${this.token.start}`)
    if (this.is(':')) {
      const pair = this.open('pair', start)
      pair.add(key, 'key')
      this.expect(':', pair)
      pair.add(this.parseAssignment(), 'value')
      return this.close(pair)
    }
    if (key.type !== 'property_identifier') throw new ParseError(`expected ":" at ${this.token.start}`)
    // `{ a }` and `{ a = 1 }` (the latter only inside a destructuring target,
    // which parseBindingTarget handles; here it is a syntax error we fail on).
    if (this.is('=')) throw new ParseError(`unexpected "=" at ${this.token.start}`)
    return this.make('shorthand_property_identifier', key.startIndex, key.endIndex)
  }

  // ---- JSX -----------------------------------------------------------------

  private parseJsx(): JsNode {
    const state = this.save()
    try {
      return this.parseJsxElement(false)
    } catch (error) {
      // In .tsx a leading `<` may instead open a generic arrow's type
      // parameters (`<T,>(x) => x`); retry that reading before giving up.
      if (this.dialect !== 'tsx') throw error
      this.restore(state)
      const scratch = this.open('type_parameters')
      this.skipAngleBracketed(scratch)
      const arrow = this.tryParseArrowFunction()
      if (!arrow) throw error
      return arrow
    }
  }

  /**
   * `resumeRaw` says what follows this element: inside another element's
   * children the next thing is markup, so the lexer must stay parked instead of
   * tokenizing `</div>` as operators. Everywhere else a normal token follows.
   */
  private parseJsxElement(resumeRaw: boolean): JsNode {
    const start = this.token.start
    if (this.lexer.text[start] !== '<') throw new ParseError('expected JSX')
    const fragment = this.jsxFragmentAhead()
    const opening = this.parseJsxOpening(resumeRaw, fragment)
    if (opening.type === 'jsx_self_closing_element') return opening
    const element = this.open(fragment ? 'jsx_fragment' : 'jsx_element', start)
    element.add(opening, 'open_tag')
    for (let i = 0; i < 100_000; i++) {
      if (this.parseJsxChild(element, resumeRaw) === 'closed') return this.close(element)
    }
    throw new ParseError('JSX element too long')
  }

  /**
   * A JSX tag closes on a single `>` CHARACTER, which the tokenizer's maximal
   * munch would happily swallow into `>=` or `>>`. `<code>==</code>` is real
   * markup, so every tag boundary is tested against the source text, never
   * against a token.
   */
  private atJsxGt(): boolean {
    return this.lexer.text[this.token.start] === '>'
  }

  private jsxFragmentAhead(): boolean {
    const state = this.save()
    this.advance()
    const isFragment = this.atJsxGt()
    this.restore(state)
    return isFragment
  }

  private parseJsxOpening(elementResumeRaw: boolean, fragment: boolean): JsNode {
    // Attributes tokenize normally; only the text between tags needs raw
    // scanning, which starts the moment the tag's `>` is consumed.
    const node = this.open('jsx_opening_element')
    this.expect('<', node)
    if (fragment) {
      this.consumeJsxTagEnd(node, true)
      return this.close(node)
    }
    node.add(this.parseJsxName(), 'name')
    while (!this.atJsxGt() && !this.is('/')) {
      if (this.atEof()) throw new ParseError('unterminated JSX tag')
      if (this.is('{')) {
        const spread = this.open('jsx_expression')
        this.take(spread)
        this.eat('...', spread)
        spread.add(this.parseAssignment())
        this.expect('}', spread)
        node.add(this.close(spread))
        continue
      }
      const attribute = this.open('jsx_attribute')
      attribute.add(this.parseJsxName(), 'name')
      if (this.is('=')) {
        // Consume `=` WITHOUT lexing ahead: the value may be a multi-line
        // attribute string, which the JS string tokenizer would reject.
        attribute.add(this.make('=', this.token.start, this.token.end, false))
        this.lexer.pos = this.token.end
        const valueStart = this.lexer.peekPosition()
        const quote = this.lexer.text[valueStart]
        if (quote === '"' || quote === "'") {
          attribute.add(this.parseJsxAttributeString(valueStart))
        } else {
          this.prevEnd = this.lexer.pos
          this.token = this.lexer.next(false)
          if (this.is('{')) attribute.add(this.parseJsxExpressionContainer(false))
          else if (this.lexer.text[this.token.start] === '<') attribute.add(this.parseJsxElement(false))
          else throw new ParseError(`bad JSX attribute value at ${this.token.start}`)
        }
      }
      node.add(this.close(attribute))
    }
    if (this.is('/')) {
      const selfClosing = this.make('jsx_self_closing_element', node.startIndex, node.endIndex)
      for (const child of node.children) selfClosing.add(child)
      const name = node.childForFieldName('name')
      if (name) selfClosing.setField('name', name)
      this.expect('/', selfClosing)
      this.consumeJsxTagEnd(selfClosing, elementResumeRaw)
      return this.close(selfClosing)
    }
    this.consumeJsxTagEnd(node, true)
    return this.close(node)
  }

  /** Consume a tag's `>`, then either park the lexer for raw child text or
   *  resume normal tokenization. */
  private consumeJsxTagEnd(node: JsNode, resumeRaw: boolean): void {
    if (!this.atJsxGt()) throw new ParseError(`expected ">" at ${this.token.start}`)
    const end = this.token.start + 1
    node.add(this.make('>', this.token.start, end, false))
    this.lexer.pos = end
    this.prevEnd = end
    this.token = resumeRaw
      ? { kind: 'punct', start: end, end, value: '', newlineBefore: false }
      : this.lexer.next(false)
  }

  private parseJsxChild(element: JsNode, elementResumeRaw: boolean): 'closed' | 'child' {
    const text = this.lexer.text
    let i = this.lexer.pos
    const textStart = i
    while (i < text.length && text[i] !== '<' && text[i] !== '{') i++
    if (i > textStart && text.slice(textStart, i).trim().length > 0) {
      element.add(this.make('jsx_text', textStart, i))
    }
    if (i >= text.length) throw new ParseError('unterminated JSX element')
    this.lexer.pos = i
    if (text[i] === '{') {
      this.token = this.lexer.next(false)
      element.add(this.parseJsxExpressionContainer(true))
      return 'child'
    }
    this.token = this.lexer.next(false)
    if (text[i + 1] === '/') {
      const closing = this.open('jsx_closing_element', i)
      this.expect('<', closing)
      this.expect('/', closing)
      if (!this.atJsxGt()) closing.add(this.parseJsxName(), 'name')
      this.consumeJsxTagEnd(closing, elementResumeRaw)
      element.add(this.close(closing), 'close_tag')
      return 'closed'
    }
    element.add(this.parseJsxElement(true))
    return 'child'
  }

  /**
   * A JSX attribute string is markup, not a JS literal: it may span lines and
   * processes no escapes, so a multi-line `className="…"` must be read raw
   * rather than handed to the string tokenizer.
   */
  private parseJsxAttributeString(start: number): JsNode {
    const text = this.lexer.text
    const quote = text[start]
    if (quote !== '"' && quote !== "'") throw new ParseError(`expected JSX attribute string at ${start}`)
    const closing = text.indexOf(quote, start + 1)
    if (closing === -1) throw new ParseError(`unterminated JSX attribute string at ${start}`)
    const node = this.make('string', start, closing + 1)
    if (closing > start + 1) node.add(this.make('string_fragment', start + 1, closing))
    this.lexer.pos = closing + 1
    this.prevEnd = this.lexer.pos
    this.token = this.lexer.next(false)
    return node
  }

  private parseJsxExpressionContainer(resumeRaw: boolean): JsNode {
    const node = this.open('jsx_expression')
    this.expect('{', node)
    if (!this.is('}')) {
      this.eat('...', node)
      node.add(this.parseExpression())
    }
    if (!this.is('}')) throw new ParseError(`expected "}" at ${this.token.start}`)
    const end = this.token.start + 1
    node.add(this.make('}', this.token.start, end, false))
    this.lexer.pos = end
    this.prevEnd = end
    this.close(node, end)
    this.token = resumeRaw
      ? { kind: 'punct', start: end, end, value: '', newlineBefore: false }
      : this.lexer.next(false)
    return node
  }

  private parseJsxName(): JsNode {
    const start = this.token.start
    if (this.token.kind !== 'identifier') throw new ParseError(`expected JSX name at ${start}`)
    let node = this.parseIdentifier('identifier')
    for (let i = 0; i < 32; i++) {
      if (this.is(':') || this.is('-')) {
        this.advance()
        if (this.token.kind !== 'identifier') throw new ParseError('bad JSX name')
        this.advance()
        node = this.close(this.make('jsx_namespace_name', start, this.prevEnd), this.prevEnd)
        continue
      }
      if (this.is('.')) {
        const member = this.open('member_expression', start)
        member.add(node, 'object')
        this.take(member)
        member.add(this.parseIdentifier('property_identifier'), 'property')
        node = this.close(member)
        continue
      }
      break
    }
    return node
  }
}
