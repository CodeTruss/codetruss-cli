import type { SyntaxNode } from '../lang'

/**
 * Tree-sitter-shaped nodes over a plain source string.
 *
 * Spans are offsets, not substrings: `text` slices on demand and row/column come
 * from a line table by binary search. A 400 KB file therefore costs one string
 * plus one Int32Array, not one substring per node.
 */

export class Source {
  readonly text: string
  /** Offset of the first character of each line. */
  private readonly lineStarts: Int32Array

  constructor(text: string) {
    this.text = text
    const starts: number[] = [0]
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i)
      // \n, \r (bare or CRLF), U+2028, U+2029 all start a new line.
      if (c === 10) starts.push(i + 1)
      else if (c === 13) {
        if (text.charCodeAt(i + 1) === 10) i++
        starts.push(i + 1)
      } else if (c === 0x2028 || c === 0x2029) starts.push(i + 1)
    }
    this.lineStarts = Int32Array.from(starts)
  }

  /** 0-based row/column for an offset. */
  pointAt(offset: number): { row: number; column: number } {
    const starts = this.lineStarts
    let lo = 0
    let hi = starts.length - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1
      if (starts[mid] <= offset) lo = mid
      else hi = mid - 1
    }
    return { row: lo, column: offset - starts[lo] }
  }

  /** 0-based row for an offset — the hot path (every finding location). */
  rowAt(offset: number): number {
    return this.pointAt(offset).row
  }
}

export class JsNode implements SyntaxNode {
  readonly type: string
  readonly isNamed: boolean
  readonly id: number
  startIndex: number
  endIndex: number
  parent: JsNode | null = null
  readonly children: JsNode[] = []
  private fieldMap: Map<string, JsNode> | null = null
  private namedCache: JsNode[] | null = null
  private readonly source: Source

  constructor(source: Source, type: string, isNamed: boolean, startIndex: number, endIndex: number, id: number) {
    this.source = source
    this.type = type
    this.isNamed = isNamed
    this.startIndex = startIndex
    this.endIndex = endIndex
    this.id = id
  }

  get text(): string {
    return this.source.text.slice(this.startIndex, this.endIndex)
  }

  get startPosition(): { row: number; column: number } {
    return this.source.pointAt(this.startIndex)
  }

  get endPosition(): { row: number; column: number } {
    return this.source.pointAt(this.endIndex)
  }

  get childCount(): number {
    return this.children.length
  }

  get namedChildren(): JsNode[] {
    if (!this.namedCache) this.namedCache = this.children.filter((child) => child.isNamed)
    return this.namedCache
  }

  get namedChildCount(): number {
    return this.namedChildren.length
  }

  get previousNamedSibling(): JsNode | null {
    if (!this.parent) return null
    const siblings = this.parent.namedChildren
    const index = siblings.indexOf(this)
    return index > 0 ? siblings[index - 1] : null
  }

  get nextNamedSibling(): JsNode | null {
    if (!this.parent) return null
    const siblings = this.parent.namedChildren
    const index = siblings.indexOf(this)
    return index >= 0 && index + 1 < siblings.length ? siblings[index + 1] : null
  }

  child(index: number): JsNode | null {
    return this.children[index] ?? null
  }

  childForFieldName(fieldName: string): JsNode | null {
    return this.fieldMap?.get(fieldName) ?? null
  }

  // ---- construction (parser-internal) ----

  add(child: JsNode, field?: string): JsNode {
    child.parent = this
    this.children.push(child)
    this.namedCache = null
    if (field) {
      if (!this.fieldMap) this.fieldMap = new Map()
      // Tree-sitter keeps the FIRST child bound to a field when a rule repeats
      // one (e.g. sequence_expression left/right); match that.
      if (!this.fieldMap.has(field)) this.fieldMap.set(field, child)
    }
    return child
  }

  /** Re-key an existing child under a field name (used when a node is reshaped). */
  setField(field: string, child: JsNode): void {
    if (!this.fieldMap) this.fieldMap = new Map()
    this.fieldMap.set(field, child)
  }
}
