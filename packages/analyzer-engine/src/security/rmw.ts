import type { SastLanguage, SyntaxNode } from './lang'
import { asCall, asFunction, asMember, dottedName, isFunctionNode, unwrap, type NCall } from './normalize'

/**
 * Read-modify-write race detection (CWE-362) — the one concurrency shape a
 * file-local AST rule can prove.
 *
 * This lives outside rules.ts because it is the only rule that reasons across
 * STATEMENTS rather than over one node: it pairs a read with a later write in
 * the same function scope. Keeping the pair search here also keeps the rule
 * pack readable — rules.ts only carries the metadata and the receiver gate.
 *
 * The predicate is deliberately narrow. A measured probe over this repo plus
 * five sweep repos found that the loose shape (any read followed by a write to
 * the same model) yields 20 pairs of which 17 are benign — CAS updates,
 * transactional claims, unrelated writes. Requiring the write's payload to be
 * ARITHMETIC on a field of the read result is the entire difference between a
 * useless rule and a clean one, so every clause below is load-bearing:
 *
 *   1. `const V = await <db>.<model>.find*({ where: K })`  — awaited, bound
 *   2. `<db>.<model>.update({ where: K', data: D })`       — later, same scope
 *   3. K ≡ K'                                              — same row, keyed identically
 *   4. D contains `V.<field> <arith> …`                    — the write recomputes what it read
 *   5. no transaction / tx receiver / row lock around the pair
 *
 * Clause 4 is also what keeps the FIX silent: the atomic operator idiom
 * (`data: { balance: { increment: amount } }`) is an object, never a binary
 * arithmetic expression, so it can never match. Likewise a last-write-wins
 * overwrite (`data: { name }`) carries no arithmetic and never fires.
 */

const lc = (s: string | null | undefined) => (s ?? '').toLowerCase()

/** Reads that return a single record whose fields can be recomputed. */
const READ_METHODS = new Set([
  'findunique',
  'finduniqueorthrow',
  'findfirst',
  'findfirstorthrow',
  'findone',
])
/** The update family. `create` cannot lose an update; `delete` writes no value. */
const WRITE_METHODS = new Set(['update', 'updatemany'])
/** Transaction wrappers: inside one, the read and the write are already atomic. */
const TX_METHODS = new Set(['transaction', 'runintransaction', 'withtransaction', 'intransaction', 'transact'])
/** Transaction-callback receivers (`tx.invoice.update`) — the same knowledge
 *  db-call-in-loop leans on, stated here because a `tx` receiver also passes
 *  the rule pack's DB_RECEIVER when it appears as `db.tx` or `this.trx`. */
const TX_RECEIVER = /(^|[._])(tx|trx)([._]|$)/i
/** Explicit row locking in raw SQL anywhere in the enclosing scope. */
const ROW_LOCK = /\bfor\s+update\b|advisory_?(xact_)?lock/i
/** Binary operators that recompute a value from what was read. */
const ARITHMETIC_OPS = new Set(['+', '-', '*', '/', '%'])

/** Structurally a `PatternHit` — declared locally so this module never has to
 *  import from rules.ts (that edge would close an import cycle). */
export interface RmwHit {
  node: SyntaxNode
  line: number
  detail: string
}

/**
 * Report the read of an unguarded read-modify-write pair, anchored on the
 * binding — that is where a reviewer starts reading, and the detail names the
 * write line. `dbReceiver` is the rule pack's DB_RECEIVER, passed in rather
 * than imported for the cycle reason above.
 */
export function readModifyWriteHits(
  node: SyntaxNode,
  lang: SastLanguage,
  dbReceiver: RegExp,
): RmwHit[] {
  if (node.type !== 'variable_declarator') return []
  const nameNode = node.childForFieldName('name')
  if (nameNode?.type !== 'identifier') return []
  const binding = nameNode.text
  // Awaited only: an un-awaited read binds a promise, so nothing downstream can
  // read a field off it and write it back.
  const value = node.childForFieldName('value')
  if (value?.type !== 'await_expression') return []
  const read = asCall(unwrap(value, lang), lang)
  if (!read || read.isConstruct) return []
  if (!READ_METHODS.has(lc(read.method))) return []
  // `db.invoice` — the receiver identifies both the client and the model, so
  // requiring the write to carry the SAME receiver is the same-model test.
  const target = read.receiverName
  if (!target || !dbReceiver.test(target) || TX_RECEIVER.test(target)) return []
  const readWhere = whereShape(read, lang)
  if (!readWhere) return []
  if (enclosedByTransaction(node, lang)) return []

  const scope = enclosingScope(node, lang)
  if (!scope) return []
  for (const write of laterWrites(scope, read.node, lang)) {
    if (write.receiverName !== target) continue
    const arg = write.args[0]
    if (!arg || unwrap(arg, lang).type !== 'object') continue
    const payload = objectValue(unwrap(arg, lang), 'data')
    const writeWhere = objectValue(unwrap(arg, lang), 'where')
    if (!payload || !writeWhere) continue
    // Same row, keyed identically. An extra key in the write's where is a
    // compare-and-set guard (`{ id, status: 'PROPOSED' }`), not a blind write.
    const shape = keyShape(unwrap(writeWhere, lang))
    if (!shape || !sameShape(readWhere, shape)) continue
    const source = arithmeticOnBinding(unwrap(payload, lang), binding, lang)
    if (!source) continue
    if (ROW_LOCK.test(scope.text)) return []
    return [
      {
        node: read.node,
        line: read.line,
        detail: `${write.fullName} (line ${write.line}) recomputes ${source.field} from ${source.ref}`,
      },
    ]
  }
  return []
}

/** `{ where: { … } }` of a call's first argument, normalized to key → value. */
function whereShape(call: NCall, lang: SastLanguage): Map<string, string> | null {
  const arg = call.args[0]
  if (!arg) return null
  const obj = unwrap(arg, lang)
  if (obj.type !== 'object') return null
  const where = objectValue(obj, 'where')
  return where ? keyShape(unwrap(where, lang)) : null
}

/** Value node of an object literal's `key:` property, or null. */
function objectValue(obj: SyntaxNode, key: string): SyntaxNode | null {
  if (obj.type !== 'object') return null
  for (const child of obj.namedChildren) {
    if (child.type !== 'pair') continue
    const k = child.childForFieldName('key')?.text?.replace(/['"]/g, '')
    if (k === key) return child.childForFieldName('value')
  }
  return null
}

/**
 * An object literal's keys mapped to their whitespace-stripped value text, so
 * `{ id }` and `{ id: id }` compare equal. Returns null for anything not
 * comparable by text (a spread, a computed key, an empty object) — an
 * unprovable key match must never count as a match.
 */
function keyShape(obj: SyntaxNode): Map<string, string> | null {
  if (obj.type !== 'object') return null
  const out = new Map<string, string>()
  for (const child of obj.namedChildren) {
    if (child.type === 'shorthand_property_identifier') {
      out.set(child.text, child.text)
      continue
    }
    if (child.type !== 'pair') return null
    const k = child.childForFieldName('key')?.text?.replace(/['"]/g, '')
    const v = child.childForFieldName('value')?.text
    if (!k || v === undefined) return null
    out.set(k, v.replace(/\s+/g, ''))
  }
  return out.size > 0 ? out : null
}

function sameShape(a: Map<string, string>, b: Map<string, string>): boolean {
  if (a.size !== b.size) return false
  for (const [k, v] of a) if (b.get(k) !== v) return false
  return true
}

/**
 * A binary arithmetic expression inside the write payload whose operand IS a
 * field access on the read binding (`balance: inv.balance + amount`). The
 * operand must be the member access itself: a value derived through a call
 * (`inv.createdAt.getTime() + 1000`) is not the lost-update shape.
 */
function arithmeticOnBinding(
  data: SyntaxNode,
  binding: string,
  lang: SastLanguage,
): { field: string; ref: string } | null {
  const found: Array<{ field: string; ref: string }> = []
  const visit = (n: SyntaxNode) => {
    if (found.length > 0) return
    if (n.type === 'binary_expression' && ARITHMETIC_OPS.has(n.childForFieldName('operator')?.text ?? '')) {
      const left = n.childForFieldName('left')
      const right = n.childForFieldName('right')
      const ref =
        (left ? bindingField(left, binding, lang) : null) ??
        (right ? bindingField(right, binding, lang) : null)
      if (ref) {
        found.push({ field: writtenField(n) ?? ref.slice(ref.lastIndexOf('.') + 1), ref })
        return
      }
    }
    for (const c of n.namedChildren) visit(c)
  }
  visit(data)
  return found[0] ?? null
}

/** Dotted name of a field access rooted at `binding`, or null. */
function bindingField(operand: SyntaxNode, binding: string, lang: SastLanguage): string | null {
  const n = unwrap(operand, lang)
  if (!asMember(n, lang)) return null
  const name = dottedName(n, lang)
  return name && name.startsWith(`${binding}.`) ? name : null
}

/** The payload key the arithmetic lands in, for the finding's detail line. */
function writtenField(from: SyntaxNode): string | null {
  let cur: SyntaxNode | null = from.parent
  for (let i = 0; i < 8 && cur; i++) {
    if (cur.type === 'pair') return cur.childForFieldName('key')?.text?.replace(/['"]/g, '') ?? null
    cur = cur.parent
  }
  return null
}

/** True when any enclosing call is a transaction wrapper. */
function enclosedByTransaction(from: SyntaxNode, lang: SastLanguage): boolean {
  let cur: SyntaxNode | null = from.parent
  for (let i = 0; i < 80 && cur; i++) {
    const call = asCall(cur, lang)
    if (call && TX_METHODS.has(lc(call.method).replace(/^\$/, ''))) return true
    cur = cur.parent
  }
  return false
}

/** Body of the function the node lives in, or the program root at module scope. */
function enclosingScope(from: SyntaxNode, lang: SastLanguage): SyntaxNode | null {
  let cur: SyntaxNode | null = from.parent
  for (let i = 0; i < 80 && cur; i++) {
    if (isFunctionNode(cur, lang)) return asFunction(cur, lang)?.body ?? null
    if (!cur.parent) return cur
    cur = cur.parent
  }
  return null
}

/**
 * Update-family calls in the same scope that start after the read ends. Nested
 * function scopes are not descended into: a write inside a callback runs under
 * a different ordering than the statement sequence this rule reasons about.
 */
function laterWrites(scope: SyntaxNode, read: SyntaxNode, lang: SastLanguage): NCall[] {
  const out: NCall[] = []
  const visit = (n: SyntaxNode) => {
    if (n !== scope && isFunctionNode(n, lang)) return
    if (n.startIndex >= read.endIndex) {
      const call = asCall(n, lang)
      if (call && !call.isConstruct && WRITE_METHODS.has(lc(call.method))) out.push(call)
    }
    for (const c of n.namedChildren) visit(c)
  }
  visit(scope)
  return out
}
