import { MAX_SOURCE_BYTES, type ParsedTree, type SastLanguage, type SastParser } from '../lang'
import { parseJs, type JsDialect } from './parser'

export { ParseError } from './lexer'
export { parseJs } from './parser'
export type { JsDialect } from './parser'

const DIALECTS: Record<string, JsDialect> = {
  javascript: 'javascript',
  typescript: 'typescript',
  tsx: 'tsx',
}

const JS_LANGUAGES: ReadonlySet<SastLanguage> = new Set<SastLanguage>(['javascript', 'typescript', 'tsx'])

/**
 * The CLI's SAST parser: JavaScript, TypeScript and TSX, no dependencies.
 *
 * Returns null — degrading that file to "not analyzed" — for any source it
 * cannot parse exactly, including every non-JS language. That is the honest
 * answer and the safe one: the CLI's receipt reports degraded languages, and a
 * file we could not read never produces a finding.
 */
export const zeroDependencyJsParser: SastParser = {
  languages: JS_LANGUAGES,
  async parse(lang: SastLanguage, content: string): Promise<ParsedTree | null> {
    const dialect = DIALECTS[lang]
    if (!dialect) return null
    if (content.length > MAX_SOURCE_BYTES) return null
    try {
      const rootNode = parseJs(content, dialect)
      return { rootNode, hasError: false, release: () => {} }
    } catch {
      return null
    }
  },
}
