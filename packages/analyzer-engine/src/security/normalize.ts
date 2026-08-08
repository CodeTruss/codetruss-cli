import type { SastLanguage, SyntaxNode } from './lang'
import { isJsFamily } from './lang'

/**
 * Normalized AST adapter.
 *
 * Tree-sitter grammars disagree on node names (`call_expression` vs `call` vs
 * `method_invocation` vs `invocation_expression`), so this layer projects each
 * grammar onto ONE small vocabulary the rules and taint engine speak: calls,
 * member/property access, string concatenation, string interpolation,
 * subscripts, assignments and function definitions. Rules never touch a raw
 * grammar node type; they ask questions like "is this a call to X, and is arg N
 * tainted?" — the same question in every language.
 *
 * Everything here is total: unknown shapes return null / empty, never throw.
 */

const field = (n: SyntaxNode, name: string): SyntaxNode | null => n.childForFieldName(name)

/** Strip surrounding quotes / string prefixes from a raw literal token. */
function stripStringToken(raw: string): string {
  let s = raw.trim()
  // language string prefixes: f"" r"" b"" u"" (python), @"" $"" (c#), L"" etc.
  s = s.replace(/^[a-zA-Z@$]{1,2}(?=['"])/, '')
  const q = s[0]
  if ((q === '"' || q === "'" || q === '`') && s.endsWith(q)) return s.slice(1, -1)
  return s
}

// ---- node-type vocabularies per language ----------------------------------

const FUNCTION_TYPES: Record<SastLanguage, Set<string>> = {
  javascript: new Set(['function_declaration', 'function_expression', 'arrow_function', 'method_definition', 'generator_function_declaration', 'generator_function']),
  typescript: new Set(['function_declaration', 'function_expression', 'arrow_function', 'method_definition', 'generator_function_declaration', 'generator_function']),
  tsx: new Set(['function_declaration', 'function_expression', 'arrow_function', 'method_definition', 'generator_function_declaration', 'generator_function']),
  python: new Set(['function_definition', 'lambda']),
  java: new Set(['method_declaration', 'constructor_declaration', 'lambda_expression']),
  csharp: new Set(['method_declaration', 'constructor_declaration', 'local_function_statement', 'lambda_expression']),
  go: new Set(['function_declaration', 'method_declaration', 'func_literal']),
  php: new Set(['function_definition', 'method_declaration', 'anonymous_function_creation_expression', 'arrow_function']),
  ruby: new Set(['method', 'singleton_method']),
  rust: new Set(['function_item', 'closure_expression']),
}

export function isFunctionNode(node: SyntaxNode, lang: SastLanguage): boolean {
  return FUNCTION_TYPES[lang].has(node.type)
}

export interface NFunc {
  name: string
  params: string[]
  body: SyntaxNode | null
  node: SyntaxNode
  line: number
}

export function asFunction(node: SyntaxNode, lang: SastLanguage): NFunc | null {
  if (!isFunctionNode(node, lang)) return null
  const name = field(node, 'name')?.text ?? '<anonymous>'
  const body = field(node, 'body') ?? null
  return { name, params: paramNames(node), body, node, line: node.startPosition.row + 1 }
}

/** The parameter container for a function node; grammars name it differently. */
function paramContainer(node: SyntaxNode): SyntaxNode | null {
  const containerTypes = new Set([
    'formal_parameters', 'parameters', 'parameter_list', 'method_parameters',
    'formal_parameter_list', 'block_parameters', 'closure_parameters',
  ])
  const container = field(node, 'parameters')
  if (container) return container
  for (let i = 0; i < node.childCount; i++) {
    const c = node.child(i)
    if (c && containerTypes.has(c.type)) return c
  }
  return null
}

/**
 * EVERY name a function's signature binds, including the leaves of a
 * destructuring pattern (`({ ctx, input })`, `({ params }: Props)`).
 *
 * Distinct from {@link paramNames}, which returns POSITIONAL parameters and
 * feeds the interprocedural summary — a destructured leaf has no argument
 * position, so it cannot appear there. This set answers a different question:
 * "did this function's signature introduce this identifier?" Destructuring is
 * how request-handling code normally binds its request, so a gate that only
 * saw positional names would miss the majority of real handlers.
 *
 * Over-approximates slightly: an identifier inside a default-value expression
 * (`function f(a = fallback)`) is collected too. That only ever makes the gate
 * more permissive, which is the safe direction for a precision narrowing.
 */
export function paramBoundNames(node: SyntaxNode): Set<string> {
  const names = new Set<string>()
  const add = (n: SyntaxNode | null): void => {
    if (!n) return
    if (n.type === 'identifier' || n.type === 'shorthand_property_identifier_pattern') {
      names.add(n.text)
      return
    }
    if (n.type === 'variable_name') {
      names.add(n.text.replace(/^\$/, ''))
      return
    }
    // Type annotations contribute `type_identifier`, not `identifier`, so a
    // blanket descent does not pull type names in.
    for (const c of n.namedChildren) add(c)
  }
  const container = paramContainer(node)
  if (container) for (const c of container.namedChildren) add(c)
  else add(field(node, 'parameter'))
  return names
}

function paramNames(node: SyntaxNode): string[] {
  const container = paramContainer(node)
  // JS arrow with a single bare identifier param: `x => ...`
  if (!container) {
    const p = field(node, 'parameter')
    if (p) return [leafParamName(p) ?? p.text].filter(Boolean) as string[]
    return []
  }
  const names: string[] = []
  for (const c of container.namedChildren) {
    // Go groups several names under one parameter_declaration.
    if (c.type === 'parameter_declaration') {
      for (const id of c.namedChildren) if (id.type === 'identifier') names.push(id.text)
      continue
    }
    const n = leafParamName(c)
    if (n) names.push(n)
  }
  return names
}

function leafParamName(p: SyntaxNode): string | null {
  switch (p.type) {
    case 'identifier':
    case 'shorthand_property_identifier_pattern':
      return p.text
    case 'variable_name': // php
      return p.text.replace(/^\$/, '')
    default: {
      // required_parameter/optional_parameter (TS), typed_parameter (py),
      // default_parameter, formal_parameter (java), parameter (c#/rust),
      // simple_parameter (php): the name is a nested identifier/variable_name.
      const named = field(p, 'name') ?? field(p, 'pattern')
      if (named) {
        if (named.type === 'identifier') return named.text
        if (named.type === 'variable_name') return named.text.replace(/^\$/, '')
      }
      for (const c of p.namedChildren) {
        if (c.type === 'identifier') return c.text
        if (c.type === 'variable_name') return c.text.replace(/^\$/, '')
      }
      return null
    }
  }
}

// ---- expression normalization ---------------------------------------------

/** Strip parentheses / await / casts so callers see through wrappers. */
export function unwrap(node: SyntaxNode, lang: SastLanguage): SyntaxNode {
  let cur = node
  for (let i = 0; i < 12; i++) {
    const t = cur.type
    if (t === 'parenthesized_expression' || t === 'await_expression') {
      const inner = t === 'await_expression' ? (field(cur, 'argument') ?? cur.namedChildren[0]) : cur.namedChildren[0]
      if (inner) {
        cur = inner
        continue
      }
    }
    if (isJsFamily(lang) && (t === 'as_expression' || t === 'satisfies_expression' || t === 'non_null_expression')) {
      const inner = cur.namedChildren[0]
      if (inner) {
        cur = inner
        continue
      }
    }
    if (lang === 'csharp' && (t === 'cast_expression')) {
      const inner = field(cur, 'value') ?? cur.namedChildren[cur.namedChildren.length - 1]
      if (inner) {
        cur = inner
        continue
      }
    }
    break
  }
  return cur
}

export interface NCall {
  node: SyntaxNode
  line: number
  callee: SyntaxNode | null
  /** Dotted callee name, e.g. "child_process.exec", "cursor.execute", "os.system". */
  fullName: string
  /** Last dotted segment, e.g. "exec". */
  method: string
  /** Object of a member/method call, e.g. `db` in `db.query()`. */
  receiver: SyntaxNode | null
  /** Dotted receiver name, e.g. "child_process", "os". */
  receiverName: string | null
  args: SyntaxNode[]
  /** True for `new X()` / object-creation expressions. */
  isConstruct: boolean
}

/**
 * True when the expression is a TAGGED TEMPLATE LITERAL — ``tag`…${x}…` ``.
 *
 * The distinction from a plain template literal is structural, not lexical: a
 * tagged template hands the static text and each interpolated value to the tag
 * as SEPARATE arguments. The values never enter the string, so the tag — not
 * the caller — decides how they are combined. For a query builder that is
 * exactly parameter binding, which is why this shape is the *safe*
 * construction of every SQL library that offers it (drizzle's `sql`, Prisma's
 * `$queryRaw`, postgres.js, slonik, `@vercel/postgres`) and why an untagged
 * ``db.query(`… ${x}`)`` — where the value IS concatenated into the string —
 * is not this shape and keeps its finding.
 *
 * Expressed as a shape rather than a list of tag names so a library we have
 * never heard of is covered without another patch. The residual unsoundness is
 * stated: a tag that concatenates rather than binds would be exempted too. No
 * SQL library does that, and the escape hatches that exist for it are named
 * calls (`sql.raw`, `$queryRawUnsafe`) which remain sinks in their own right.
 */
export function isTaggedTemplate(node: SyntaxNode, lang: SastLanguage): boolean {
  if (!isJsFamily(lang)) return false
  const n = unwrap(node, lang)
  if (n.type !== 'call_expression') return false
  return field(n, 'arguments')?.type === 'template_string'
}

const CALL_TYPES: Record<SastLanguage, Set<string>> = {
  javascript: new Set(['call_expression', 'new_expression']),
  typescript: new Set(['call_expression', 'new_expression']),
  tsx: new Set(['call_expression', 'new_expression']),
  python: new Set(['call']),
  java: new Set(['method_invocation', 'object_creation_expression', 'explicit_constructor_invocation']),
  csharp: new Set(['invocation_expression', 'object_creation_expression']),
  go: new Set(['call_expression']),
  php: new Set(['function_call_expression', 'member_call_expression', 'scoped_call_expression', 'object_creation_expression']),
  ruby: new Set(['call', 'method_call', 'command', 'command_call']),
  rust: new Set(['call_expression', 'macro_invocation']),
}

/**
 * The callee child of a call node — what {@link asCall} reports as
 * {@link NCall.callee} — resolved without building an `NCall`.
 *
 * Split out because `dottedName` needs ONLY this. Reaching it through `asCall`
 * made naming a chained call exponential: `asCall` eagerly resolves `fullName`
 * and `receiverName` (two `dottedName` descents into the same receiver) and
 * `dottedName` then descended into the callee a third time — 3x the work per
 * link of a method chain, so `a.f().f()…` cost 3^links. An 18-link chain of
 * `str.replace()` (pygments' `escape_tex`) took hours in a 19 KB file.
 */
function calleeOf(node: SyntaxNode, lang: SastLanguage): SyntaxNode | null {
  if (lang === 'java') {
    // method_invocation names the method; object_creation/explicit_constructor
    // name the type.
    return node.type === 'method_invocation' ? field(node, 'name') : field(node, 'type')
  }
  if (lang === 'python') return field(node, 'function')
  if (lang === 'ruby') return field(node, 'method')
  if (lang === 'php') {
    if (node.type === 'object_creation_expression') {
      return node.namedChildren.find((c) => c.type === 'name' || c.type === 'qualified_name') ?? null
    }
    if (node.type === 'function_call_expression') return field(node, 'function')
    // member_call_expression / scoped_call_expression
    return field(node, 'name')
  }
  if (lang === 'rust' && node.type === 'macro_invocation') return field(node, 'macro')
  // JS family, C#, Go, Rust call_expression / new / invocation:
  return node.type === 'new_expression'
    ? field(node, 'constructor')
    : field(node, 'function') ?? field(node, 'type')
}

export function asCall(node: SyntaxNode, lang: SastLanguage): NCall | null {
  if (!CALL_TYPES[lang].has(node.type)) return null
  const line = node.startPosition.row + 1
  const isConstruct = node.type === 'new_expression' || node.type === 'object_creation_expression'
  const callee = calleeOf(node, lang)

  if (lang === 'java') {
    if (node.type === 'method_invocation') {
      const obj = field(node, 'object')
      const name = callee?.text ?? ''
      const receiverName = obj ? dottedName(obj, lang) : null
      const fullName = receiverName ? `${receiverName}.${name}` : name
      return {
        node,
        line,
        callee,
        fullName,
        method: name,
        receiver: obj,
        receiverName,
        args: argList(field(node, 'arguments')),
        isConstruct: false,
      }
    }
    // object_creation_expression: new Type(args)
    return mk(node, line, callee, null, callee?.text ?? '', argList(field(node, 'arguments')), true, lang)
  }

  if (lang === 'python') {
    return mk(node, line, callee, receiverOf(callee, lang), lastSegment(callee, lang), argList(field(node, 'arguments')), false, lang)
  }

  if (lang === 'ruby') {
    const recv = field(node, 'receiver')
    return mk(node, line, callee, recv, callee?.text ?? '', argList(field(node, 'arguments')), false, lang)
  }

  if (lang === 'php') {
    if (node.type === 'object_creation_expression') {
      return mk(node, line, callee, null, callee?.text ?? '', argList(field(node, 'arguments')), true, lang)
    }
    if (node.type === 'function_call_expression') {
      return mk(node, line, callee, null, callee?.text?.replace(/^\\/, '') ?? '', argList(field(node, 'arguments')), false, lang)
    }
    // member_call_expression / scoped_call_expression
    const obj = field(node, 'object') ?? field(node, 'scope')
    return mk(node, line, callee, obj, callee?.text ?? '', argList(field(node, 'arguments')), false, lang)
  }

  if (lang === 'rust' && node.type === 'macro_invocation') {
    return mk(node, line, callee, null, callee?.text ?? '', argList(node.namedChildren.find((c) => c.type === 'token_tree') ?? null), false, lang)
  }

  // JS family, C#, Go, Rust call_expression / new / invocation:
  return mk(node, line, callee, receiverOf(callee, lang), lastSegment(callee, lang), argList(field(node, 'arguments')), isConstruct, lang)
}

function mk(
  node: SyntaxNode,
  line: number,
  callee: SyntaxNode | null,
  receiver: SyntaxNode | null,
  method: string,
  args: SyntaxNode[],
  isConstruct: boolean,
  lang: SastLanguage,
): NCall {
  const fullName = callee ? dottedName(callee, lang) ?? method : method
  return {
    node,
    line,
    callee,
    fullName,
    method,
    receiver,
    receiverName: receiver ? dottedName(receiver, lang) : null,
    args,
    isConstruct,
  }
}

/** Extract argument value nodes from an arguments container, unwrapping wrappers. */
function argList(container: SyntaxNode | null): SyntaxNode[] {
  if (!container) return []
  const out: SyntaxNode[] = []
  for (const c of container.namedChildren) {
    // C#/PHP wrap each argument in an `argument` node.
    if (c.type === 'argument') {
      const inner = c.namedChildren[c.namedChildren.length - 1]
      out.push(inner ?? c)
    } else {
      out.push(c)
    }
  }
  return out
}

/** Object expression of a member/method-call callee. */
function receiverOf(callee: SyntaxNode | null, lang: SastLanguage): SyntaxNode | null {
  if (!callee) return null
  const m = asMember(callee, lang)
  return m ? m.object : null
}

/** Last dotted segment of a callee expression (the method/function name). */
function lastSegment(callee: SyntaxNode | null, lang: SastLanguage): string {
  if (!callee) return ''
  const m = asMember(callee, lang)
  if (m) return m.property
  const d = dottedName(callee, lang)
  if (!d) return callee.text
  const dot = d.lastIndexOf('.')
  return dot === -1 ? d : d.slice(dot + 1)
}

export interface NMember {
  object: SyntaxNode
  property: string
  node: SyntaxNode
}

const MEMBER_TYPES: Record<string, { object: string; property: string }> = {
  member_expression: { object: 'object', property: 'property' }, // js
  attribute: { object: 'object', property: 'attribute' }, // python
  field_access: { object: 'object', property: 'field' }, // java
  member_access_expression: { object: 'expression', property: 'name' }, // c#/php (php uses object)
  selector_expression: { object: 'operand', property: 'field' }, // go
  field_expression: { object: 'value', property: 'field' }, // rust
  scoped_identifier: { object: 'path', property: 'name' }, // rust ::
  scoped_property_access_expression: { object: 'scope', property: 'name' }, // php ::
}

export function asMember(node: SyntaxNode, lang: SastLanguage): NMember | null {
  const spec = MEMBER_TYPES[node.type]
  if (spec) {
    // php member_access_expression uses field 'object', c# uses 'expression'
    let obj = field(node, spec.object)
    if (!obj && node.type === 'member_access_expression') obj = field(node, 'object')
    const prop = field(node, spec.property)?.text
    if (obj && prop) return { object: obj, property: prop.replace(/^\$/, ''), node }
  }
  // Ruby member access is modeled as a call with a receiver and no args.
  if (lang === 'ruby' && node.type === 'call') {
    const recv = field(node, 'receiver')
    const m = field(node, 'method')?.text
    if (recv && m) return { object: recv, property: m, node }
  }
  return null
}

/**
 * Dotted textual name of a callee / reference expression, e.g. `a.b.c`,
 * `os.system`, `child_process.exec`. Subscripts collapse to their base
 * (`x.y['z']` → `x.y`). Returns null for expressions with no stable name.
 */
export function dottedName(node: SyntaxNode, lang: SastLanguage): string | null {
  const n = unwrap(node, lang)
  const m = asMember(n, lang)
  if (m) {
    const base = dottedName(m.object, lang)
    return base ? `${base}.${m.property}` : m.property
  }
  const sub = subscriptBase(n)
  if (sub) return dottedName(sub, lang)
  // `calleeOf`, not `asCall`: building an NCall here re-derives this same name
  // twice more and makes a chained call exponential in its length.
  if (CALL_TYPES[lang].has(n.type)) {
    const callee = calleeOf(n, lang)
    if (callee) return dottedName(callee, lang)
  }
  switch (n.type) {
    case 'identifier':
    case 'property_identifier':
    case 'field_identifier':
    case 'type_identifier':
    case 'name':
    case 'qualified_name':
      return n.text.replace(/^\\/, '')
    case 'variable_name': // php $x
      return n.text.replace(/^\$/, '')
    case 'this':
    case 'self':
    case 'super':
      return n.type
    default:
      return null
  }
}

/** True and the referenced name if the node is a bare variable reference. */
export function identifierName(node: SyntaxNode, lang: SastLanguage): string | null {
  const n = unwrap(node, lang)
  if (n.type === 'identifier') return n.text
  if (n.type === 'variable_name') return n.text.replace(/^\$/, '') // php
  if (lang === 'ruby' && n.type === 'identifier') return n.text
  return null
}

/** Base expression of an index/subscript access, e.g. `a[i]` → `a`. */
export function subscriptBase(node: SyntaxNode): SyntaxNode | null {
  switch (node.type) {
    case 'subscript_expression': // js
      return field(node, 'object')
    case 'subscript': // python
      return field(node, 'value') ?? field(node, 'object')
    case 'index_expression': // go/php
      return field(node, 'operand') ?? field(node, 'object') ?? node.namedChildren[0] ?? null
    case 'element_access_expression': // c#
      return field(node, 'expression')
    case 'array_access': // java
      return field(node, 'array')
    default:
      return null
  }
}

/**
 * If the node is string concatenation (`a + b`, or PHP `a . b`), return its
 * flattened operands; otherwise null. Only `+` (or `.` in PHP) counts — other
 * binary operators don't build strings.
 */
export function concatOperands(node: SyntaxNode, lang: SastLanguage): SyntaxNode[] | null {
  const n = unwrap(node, lang)
  const concatOp = lang === 'php' ? '.' : '+'
  const isBinary =
    n.type === 'binary_expression' || n.type === 'binary_operator' /* python */ || n.type === 'binary' /* ruby */
  if (!isBinary) return null
  const op = field(n, 'operator')?.text ?? operatorToken(n)
  if (op !== concatOp) return null
  const left = field(n, 'left')
  const right = field(n, 'right')
  const parts: SyntaxNode[] = []
  const push = (side: SyntaxNode | null) => {
    if (!side) return
    const nested = concatOperands(side, lang)
    if (nested) parts.push(...nested)
    else parts.push(side)
  }
  push(left)
  push(right)
  return parts.length ? parts : null
}

function operatorToken(n: SyntaxNode): string | null {
  // Fallback for grammars that expose the operator as an anonymous child.
  for (let i = 0; i < n.childCount; i++) {
    const c = n.child(i)
    if (c && !c.isNamed) return c.text
  }
  return null
}

/**
 * Embedded expressions of a string with interpolation (template literals,
 * python f-strings, c# interpolated strings, php/ruby interpolation).
 * Returns null for non-interpolated strings.
 */
export function interpolationExprs(node: SyntaxNode, lang: SastLanguage): SyntaxNode[] | null {
  const n = unwrap(node, lang)
  const interpTypes = new Set([
    'template_substitution', // js `${...}`
    'interpolation', // python f-string / c# / ruby / php
  ])
  const stringContainerTypes = new Set([
    'template_string', 'string', 'interpolated_string_expression', 'encapsed_string', 'string_literal',
  ])
  if (!stringContainerTypes.has(n.type)) return null
  const out: SyntaxNode[] = []
  const collect = (x: SyntaxNode) => {
    if (interpTypes.has(x.type)) {
      // the embedded expression is the named child (skip format specs)
      const expr = x.namedChildren.find((c) => c.type !== 'format_specifier' && c.type !== 'type_conversion')
      if (expr) out.push(expr)
      return
    }
    // php encapsed strings embed bare variable_name children directly
    if (x.type === 'variable_name') {
      out.push(x)
      return
    }
    for (const c of x.namedChildren) collect(c)
  }
  for (const c of n.namedChildren) collect(c)
  return out.length ? out : null
}

/** Content of a plain (non-interpolated) string literal, else null. */
export function stringLiteralValue(node: SyntaxNode | null | undefined, lang: SastLanguage): string | null {
  if (!node) return null
  const n = unwrap(node, lang)
  const stringTypes = new Set([
    'string', 'string_literal', 'template_string', 'interpreted_string_literal',
    'raw_string_literal', 'encapsed_string', 'char_literal',
  ])
  if (!stringTypes.has(n.type)) return null
  if (interpolationExprs(n, lang)) return null // has interpolation → not a constant
  return stripStringToken(n.text)
}

/** Ordered constituent of a string-building expression: constant text or an embedded expression. */
export type UrlPart = { kind: 'const'; text: string } | { kind: 'expr'; node: SyntaxNode }

export interface UrlHead {
  /** Constant text before the first embedded expression ('' when the string
   *  starts with one); null when the head is not a known constant. */
  constantPrefix: string | null
  /** The first embedded expression contributing to the value, if any. */
  headExpr: SyntaxNode | null
  /** All parts in source order; null when the node is not a template/concat shape. */
  parts: UrlPart[] | null
}

/** Constant string-fragment node types inside interpolated strings, per grammar. */
const STRING_FRAGMENT_TYPES = new Set([
  'string_fragment', // js
  'string_content', // python / ruby
  'interpolated_string_text', // c#
  'string_value', // php
])

/**
 * Decompose a URL-ish string expression into its head (the part that decides
 * scheme/authority) and ordered parts. For a template/interpolated string the
 * head is the constant text before the first substitution plus that
 * substitution's expression; for a `+`/concat chain it is the leading literal
 * operand(s) or the leftmost expression. Anything else is opaque: the node
 * itself is the head and there is no part decomposition.
 */
export function urlHeadOf(node: SyntaxNode, lang: SastLanguage): UrlHead {
  const n = unwrap(node, lang)

  // Template / interpolated string: fragments and substitutions in source order.
  if (interpolationExprs(n, lang)) {
    const interpTypes = new Set(['template_substitution', 'interpolation'])
    const parts: UrlPart[] = []
    const collect = (x: SyntaxNode) => {
      if (interpTypes.has(x.type)) {
        const expr = x.namedChildren.find((c) => c.type !== 'format_specifier' && c.type !== 'type_conversion')
        if (expr) parts.push({ kind: 'expr', node: expr })
        return
      }
      // php encapsed strings embed bare variable_name children directly
      if (x.type === 'variable_name') {
        parts.push({ kind: 'expr', node: x })
        return
      }
      if (STRING_FRAGMENT_TYPES.has(x.type)) {
        parts.push({ kind: 'const', text: x.text })
        return
      }
      for (const c of x.namedChildren) collect(c)
    }
    for (const c of n.namedChildren) collect(c)
    let prefix = ''
    let head: SyntaxNode | null = null
    for (const p of parts) {
      if (p.kind === 'const') prefix += p.text
      else {
        head = p.node
        break
      }
    }
    return { constantPrefix: prefix, headExpr: head, parts }
  }

  // Concatenation chain: leading literal operands form the constant prefix.
  const operands = concatOperands(n, lang)
  if (operands) {
    const parts: UrlPart[] = operands.map((o) => {
      const lit = stringLiteralValue(o, lang)
      return lit !== null ? { kind: 'const', text: lit } : { kind: 'expr', node: o }
    })
    let prefix: string | null = null
    let head: SyntaxNode | null = null
    for (const p of parts) {
      if (p.kind === 'const') prefix = (prefix ?? '') + p.text
      else {
        head = p.node
        break
      }
    }
    return { constantPrefix: prefix, headExpr: head, parts }
  }

  return { constantPrefix: null, headExpr: n, parts: null }
}

/** Boolean value of a literal, else null. */
export function boolLiteralValue(node: SyntaxNode | null | undefined, lang: SastLanguage): boolean | null {
  if (!node) return null
  const t = unwrap(node, lang).text.trim().toLowerCase()
  if (t === 'true') return true
  if (t === 'false') return false
  return null
}

/** Numeric value of an integer/float literal, else null. */
export function numberLiteralValue(node: SyntaxNode | null | undefined, lang: SastLanguage): number | null {
  if (!node) return null
  const n = unwrap(node, lang)
  if (!/literal|number|integer|float/.test(n.type)) return null
  const v = Number(n.text.replace(/[_lLfFdD]/g, ''))
  return Number.isFinite(v) ? v : null
}

// ---- assignments ----------------------------------------------------------

export interface NAssign {
  target: string
  value: SyntaxNode
}

/**
 * All simple `variable ← expression` bindings inside a function body, NOT
 * descending into nested function scopes. Multi-target assignments
 * (`a, b := f()`, `x = y = z`) are expanded per target. Member/index targets
 * (`obj.x = ...`) are ignored — the engine tracks locals only.
 */
export function collectAssignments(body: SyntaxNode, lang: SastLanguage): NAssign[] {
  const out: NAssign[] = []
  const visit = (node: SyntaxNode) => {
    if (node !== body && isFunctionNode(node, lang)) return // separate scope
    for (const a of assignmentAt(node, lang)) out.push(a)
    for (const c of node.namedChildren) visit(c)
  }
  visit(body)
  return out
}

function assignmentAt(node: SyntaxNode, lang: SastLanguage): NAssign[] {
  const t = node.type
  const pairTargets = (target: SyntaxNode | null, value: SyntaxNode | null): NAssign[] => {
    if (!target || !value) return []
    const names = targetNames(target, lang)
    // list ← list: align by index; otherwise each name gets the whole value.
    const values = target.type.includes('list') || target.type === 'tuple' || target.type === 'expression_list'
      ? valueList(value)
      : null
    if (values && values.length === names.length) {
      return names.map((n, i) => ({ target: n, value: values[i] }))
    }
    return names.map((n) => ({ target: n, value }))
  }

  switch (t) {
    case 'variable_declarator': { // js/java/c#
      const nameNode = field(node, 'name')
      const value = field(node, 'value') ?? equalsValue(node)
      if (!value) return []
      if (nameNode && PATTERN_TYPES.has(nameNode.type)) {
        return patternLeafNames(nameNode, lang).map((target) => ({ target, value }))
      }
      const name = nameNode?.text ?? leafParamName(node)
      return name ? [{ target: name.replace(/^\$/, ''), value }] : []
    }
    case 'assignment_expression': // js/java/php/c#
    case 'augmented_assignment_expression': {
      const left = field(node, 'left')
      const right = field(node, 'right')
      if (!left || !right) return []
      if (PATTERN_TYPES.has(left.type)) {
        return patternLeafNames(left, lang).map((target) => ({ target, value: right }))
      }
      const name = identifierName(left, lang)
      return name ? [{ target: name, value: right }] : []
    }
    case 'assignment': // python/ruby
    case 'augmented_assignment':
    case 'operator_assignment': {
      const left = field(node, 'left')
      const right = field(node, 'right')
      return pairTargets(left, right)
    }
    case 'short_var_declaration': // go :=
    case 'assignment_statement': { // go =
      const left = field(node, 'left')
      const right = field(node, 'right')
      return pairTargets(left, right)
    }
    case 'var_spec': { // go var x = ...
      const value = field(node, 'value')
      const names = node.namedChildren.filter((c) => c.type === 'identifier').map((c) => c.text)
      if (!value) return []
      const values = valueList(value)
      return names.map((n, i) => ({ target: n, value: values[i] ?? value }))
    }
    case 'let_declaration': { // rust
      const pat = field(node, 'pattern')
      const value = field(node, 'value')
      const name = pat ? identifierName(pat, lang) ?? (pat.type === 'identifier' ? pat.text : null) : null
      return name && value ? [{ target: name, value }] : []
    }
    default:
      return []
  }
}

/** C# variable_declarator stores its initializer under an `equals_value_clause`. */
function equalsValue(node: SyntaxNode): SyntaxNode | null {
  const clause = node.namedChildren.find((c) => c.type === 'equals_value_clause')
  if (clause) {
    const val = clause.namedChildren[clause.namedChildren.length - 1]
    if (val) return val
  }
  const eq = node.children.findIndex((c) => c.type === '=')
  if (eq !== -1) {
    for (let i = eq + 1; i < node.childCount; i++) {
      const c = node.child(i)
      if (c && c.isNamed) return c
    }
  }
  return null
}

/** Destructuring pattern node types (JS/TS). */
const PATTERN_TYPES = new Set([
  'object_pattern',
  'array_pattern',
  'object_assignment_pattern',
  'assignment_pattern',
  'rest_pattern',
  'pair_pattern',
])

/**
 * Identifiers bound by a destructuring pattern: `{ id }`, `{ q: search }`,
 * `[first]`, `{ a = 1 }`, `{ ...rest }`.
 *
 * Each leaf is bound to the WHOLE right-hand side — the same conservative
 * over-approximation `pairTargets` already makes when target and value arities
 * differ. Without this, `const { id } = req.query` keys the taint map on the
 * literal text "{ id }", so every injection rule goes blind on the idiomatic
 * Next.js/Express handler shape.
 */
function patternLeafNames(node: SyntaxNode, lang: SastLanguage, depth = 0): string[] {
  if (depth > 6) return []
  if (node.type === 'identifier' || node.type === 'shorthand_property_identifier_pattern') {
    return [node.text.replace(/^\$/, '')]
  }
  if (!PATTERN_TYPES.has(node.type)) {
    const direct = identifierName(node, lang)
    return direct ? [direct] : []
  }
  const names: string[] = []
  for (const child of node.namedChildren) {
    if (child.type === 'pair_pattern') {
      // `{ q: search }` binds the VALUE side, not the key.
      const bound = field(child, 'value') ?? child.namedChildren[child.namedChildren.length - 1]
      if (bound) names.push(...patternLeafNames(bound, lang, depth + 1))
      continue
    }
    if (child.type === 'object_assignment_pattern' || child.type === 'assignment_pattern') {
      // `{ a = fallback }` binds the LEFT side; the default is not the binding.
      const bound = field(child, 'left') ?? child.namedChildren[0]
      if (bound) names.push(...patternLeafNames(bound, lang, depth + 1))
      continue
    }
    names.push(...patternLeafNames(child, lang, depth + 1))
  }
  return names
}

function targetNames(target: SyntaxNode, lang: SastLanguage): string[] {
  const direct = identifierName(target, lang)
  if (direct) return [direct]
  if (target.type === 'identifier') return [target.text]
  // tuple/list/expression_list of identifiers
  const names: string[] = []
  for (const c of target.namedChildren) {
    const n = identifierName(c, lang) ?? (c.type === 'identifier' ? c.text : null)
    if (n) names.push(n)
  }
  return names
}

function valueList(value: SyntaxNode): SyntaxNode[] {
  if (value.type === 'expression_list' || value.type === 'tuple' || value.type.includes('list')) {
    return value.namedChildren.slice()
  }
  return [value]
}

// ---- generic walk ---------------------------------------------------------

export function walk(root: SyntaxNode, visit: (n: SyntaxNode) => void, maxNodes = 400_000): void {
  let count = 0
  const stack: SyntaxNode[] = [root]
  while (stack.length) {
    const n = stack.pop()!
    if (++count > maxNodes) return
    visit(n)
    for (let i = n.childCount - 1; i >= 0; i--) {
      const c = n.child(i)
      if (c) stack.push(c)
    }
  }
}
