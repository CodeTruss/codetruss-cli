import type { Analyzer, AnalyzerContext, AnalyzerFinding } from './types'
import type { RepoIndex } from './types'
import { REGISTRY_ONLY_ANALYSIS } from './types'
import { SUPPORTED_TREESITTER_LANGS } from './support'
import { SAST_COVERED_LANGUAGES } from './support'

/**
 * Analysis-coverage signal.
 *
 * CodeTruss analyzes languages at two different depths, and honesty means
 * disclosing which depth applied:
 *
 *  - STRUCTURE (architecture, call-graph, complexity, health): available for
 *    languages with a native TS/JS/Python extractor AND for languages parsed via
 *    tree-sitter AST (C#, Go, Java, Rust, PHP, Ruby). For all of these we extract
 *    real symbols, a call graph and complexity, so architecture/health reflect
 *    genuine structure — a well-built repo can score high on its merits and a
 *    messy one scores low on its merits.
 *
 *  - SECURITY (injection, untrusted-input, deserialization): a real SAST engine
 *    (rules + taint tracking) runs for the languages it covers
 *    (SAST_COVERED_LANGUAGES) IN THE PROFILES THAT INCLUDE THAT PASS. For those
 *    languages the security axis is EARNED — real vulns lower it, genuinely
 *    clean code scores high. For every other language we run only regex secret
 *    scanning — that is not a security review, so a clean security axis there
 *    means "we didn't look", not "it's safe".
 *
 *    Language support is only half of that premise. The SAST pass lives outside
 *    this registry, so whether it runs at all is a property of the caller
 *    (AnalyzerContext.sast), not of the languages present: a hosted QUICK scan
 *    and every local CLI run execute the registry without it. When the pass did
 *    not run, "TypeScript is SAST-covered" says nothing about this analysis, and
 *    staying silent would be the blind spot the module exists to prevent.
 *
 * Everything outside the structure set is *surface-scanned* — structure regex,
 * secrets, file size, docs — with no architecture, flow, or complexity
 * understanding and a largely empty knowledge graph. When such a language
 * dominates a repo the deep analyzers legitimately find nothing, which naive
 * scoring reads as "excellent". This module measures how much of the codebase we
 * actually understood — separately for structure and for security — so scoring +
 * the report can be upfront about scope instead of rewarding the blind spot.
 *
 * Coverage is derived from the languages map only — the same input every caller
 * (analyzer, scoring, report) already has — so all three stay consistent. In the
 * real indexer `sum(languages) === totalLoc` (both exclude markup/data
 * languages), so the language-LOC fraction is a faithful proxy for "fraction of
 * the codebase we modeled".
 */

/**
 * Languages with a native deep extractor: real import/call graph, routes, data
 * models, symbol/complexity. Keep in sync with src/lib/repo/graph.ts and
 * src/lib/repo/symbols.ts.
 */
export const DEEPLY_SUPPORTED_LANGUAGES = new Set(['TypeScript', 'JavaScript', 'Python'])

/** Tree-sitter AST languages, lowercased. Deep STRUCTURE only — not security. */
const TREESITTER_LANGUAGES = new Set(SUPPORTED_TREESITTER_LANGS.map((l) => l.toLowerCase()))

/**
 * Deep STRUCTURE support: a native extractor OR tree-sitter AST. Architecture,
 * call-graph, complexity and health are trustworthy for these languages, so the
 * architecture/health coverage cap does NOT apply to them.
 */
export function isStructureDeep(language: string): boolean {
  return DEEPLY_SUPPORTED_LANGUAGES.has(language) || TREESITTER_LANGUAGES.has(language.toLowerCase())
}

/**
 * Deep SECURITY support: languages the SAST engine (rules + taint tracking)
 * actually covers. The security coverage cap is LIFTED for these — the security
 * score is earned. Tree-sitter-only languages (C#, Go, …) are NOT in this set:
 * they get structure analysis but only regex secret scanning for security, so
 * the security cap remains for them.
 */
export function isSecurityDeep(language: string): boolean {
  return SAST_COVERED_LANGUAGES.has(language)
}

/** Below this many code LOC a repo is too small to draw coverage conclusions. */
const MIN_ANALYZABLE_LOC = 300
/** At/above this supported fraction the repo reads as well-covered. */
const COVERAGE_OK = 0.5

export interface AnalysisCoverage {
  /** Classified code LOC (sum of the languages map). */
  totalLoc: number
  /** LOC in languages with deep STRUCTURE analysis (native or tree-sitter). */
  structureLoc: number
  /** structureLoc / totalLoc, 0..1. 1 when there is no code to analyze. */
  structureRatio: number
  /** LOC in languages with deep SECURITY analysis (native extractors only). */
  securityLoc: number
  /** securityLoc / totalLoc, 0..1. 1 when there is no code to analyze. */
  securityRatio: number
  primaryLanguage: string | null
  /** Primary language has deep structure analysis (native or tree-sitter). */
  primaryStructureSupported: boolean
  /** Primary language has deep security analysis (native extractor). */
  primarySecuritySupported: boolean
  /** Languages with NO deep structure support (genuinely unsupported), most LOC first. */
  surfaceLanguages: string[]
  /** Languages with structure but not security analysis (tree-sitter), most LOC first. */
  structureOnlyLanguages: string[]
  /** True when architecture/health reflect mostly surface-only analysis. */
  structureLimited: boolean
  /** True when the security axis is mostly regex-only (no real security review). */
  securityLimited: boolean
}

/** Pure coverage computation shared by the analyzer, scoring, and the report. */
export function analysisCoverage(index: RepoIndex): AnalysisCoverage {
  const entries = Object.entries(index.languages)
  const totalLoc = entries.reduce((sum, [, loc]) => sum + loc, 0)

  let structureLoc = 0
  let securityLoc = 0
  const surface: Array<[string, number]> = []
  const structureOnly: Array<[string, number]> = []
  for (const [lang, loc] of entries) {
    const structureDeep = isStructureDeep(lang)
    const securityDeep = isSecurityDeep(lang)
    if (structureDeep) structureLoc += loc
    else surface.push([lang, loc])
    if (securityDeep) securityLoc += loc
    // Deep structure but no security review (tree-sitter languages).
    if (structureDeep && !securityDeep) structureOnly.push([lang, loc])
  }

  const structureRatio = totalLoc > 0 ? structureLoc / totalLoc : 1
  const securityRatio = totalLoc > 0 ? securityLoc / totalLoc : 1
  const primaryLanguage = index.primaryLanguage
  const primaryStructureSupported = primaryLanguage != null && isStructureDeep(primaryLanguage)
  const primarySecuritySupported = primaryLanguage != null && isSecurityDeep(primaryLanguage)
  const byLoc = (a: [string, number], b: [string, number]) => b[1] - a[1]
  const surfaceLanguages = surface.sort(byLoc).map(([lang]) => lang)
  const structureOnlyLanguages = structureOnly.sort(byLoc).map(([lang]) => lang)

  const analyzable = totalLoc >= MIN_ANALYZABLE_LOC
  // Structure is limited when a non-trivial repo is mostly languages we can't
  // parse for architecture/flow. Tree-sitter languages do NOT trip this.
  const structureLimited =
    analyzable && (!primaryStructureSupported || structureRatio < COVERAGE_OK)
  // Security is limited when most of the repo is a language we never security-
  // reviewed (only regex-scanned) — including tree-sitter languages.
  const securityLimited =
    analyzable && (!primarySecuritySupported || securityRatio < COVERAGE_OK)

  return {
    totalLoc,
    structureLoc,
    structureRatio,
    securityLoc,
    securityRatio,
    primaryLanguage,
    primaryStructureSupported,
    primarySecuritySupported,
    surfaceLanguages,
    structureOnlyLanguages,
    structureLimited,
    securityLimited,
  }
}

/**
 * Emits ONE honest disclosure when coverage is limited, matched to the actual
 * depth we reached. This is not a penalty — it tells the reader what the scores
 * do and don't cover:
 *
 *  - Genuinely unsupported language (no extractor, no tree-sitter): the strong
 *    "limited analysis" caveat — architecture/flow/complexity were NOT analyzed.
 *  - SAST pass absent from this profile while the repo has code it would have
 *    covered: the pass-level caveat — the injection classes were never examined.
 *  - Tree-sitter language (structure fully analyzed, security surface-only): the
 *    nuanced caveat — structure is real, security is secret-scanning only.
 */
export const coverageAnalyzer: Analyzer = {
  id: 'coverage',
  name: 'Analysis coverage',
  description:
    'Discloses the depth of analysis per language so a clean report is not misread as a full architecture + security review.',
  async run(index: RepoIndex, context: AnalyzerContext = REGISTRY_ONLY_ANALYSIS): Promise<AnalyzerFinding[]> {
    const coverage = analysisCoverage(index)

    if (coverage.structureLimited) {
      const lang = coverage.primaryLanguage ?? coverage.surfaceLanguages[0] ?? 'this language'
      const pct = Math.round(coverage.structureRatio * 100)
      return [
        {
          category: 'ARCHITECTURE',
          severity: 'INFO',
          title: `Limited analysis: ${lang} is not yet deeply supported`,
          description:
            `Only ${pct}% of this codebase (by lines of code) is in a language CodeTruss deeply ` +
            `analyzes for structure (TypeScript, JavaScript, Python, plus C#, Go, Java, Rust, PHP ` +
            `and Ruby via AST parsing). ${lang} is currently surface-scanned only. The scores in ` +
            `this report reflect structure, secrets, file-size and documentation checks — they do ` +
            `NOT include architecture, call-flow, data-flow or complexity analysis for ${lang}, and ` +
            `the knowledge graph is largely empty for this repo. Read the architecture and health ` +
            `scores as provisional for the ${lang} portion of the codebase.`,
          suggestion:
            `Interpret this report as a surface audit of the ${lang} code. Deep ${lang} support ` +
            `(symbol graph, call/data flow) is on the roadmap; until then, no architecture or flow ` +
            `analysis was performed for it.`,
          impactScore: 20,
          effort: 'low',
          metadata: {
            structureRatio: coverage.structureRatio,
            securityRatio: coverage.securityRatio,
            structureLoc: coverage.structureLoc,
            totalLoc: coverage.totalLoc,
            surfaceLanguages: coverage.surfaceLanguages,
          },
        },
      ]
    }

    // The SAST pass is not in this registry, so a profile can omit it entirely.
    // When it did and the repo holds a meaningful amount of code that pass
    // covers, silence would read as "nothing found" for classes nobody looked
    // for — the exact misreading the language caveats below exist to prevent.
    if (!context.sast && coverage.securityLoc >= MIN_ANALYZABLE_LOC) {
      const sastLanguages = Object.entries(index.languages)
        .filter(([lang]) => isSecurityDeep(lang))
        .sort((a, b) => b[1] - a[1])
        .map(([lang]) => lang)
      return [
        {
          category: 'SECURITY_HYGIENE',
          severity: 'INFO',
          title: 'Security static analysis did not run in this analysis profile',
          description:
            `This analysis ran the deterministic registry analyzers only. The SAST pass — the ` +
            `security rule pack plus taint tracking from untrusted source to dangerous sink — is ` +
            `not part of this profile, so it never examined the ${sastLanguages.join(', ')} code ` +
            `here (${coverage.securityLoc} lines). The classes that pass owns were not checked at ` +
            `all: SQL injection, command injection, code injection, path traversal, SSRF, open ` +
            `redirect, XSS and insecure deserialization, plus the pattern rules for hardcoded ` +
            `credentials, disabled TLS validation, weak hashes and ciphers, and insecure ` +
            `randomness. Secret scanning, dependency advisories and every other registry pass did ` +
            `run and their results stand. Read the absence of injection findings as "that analysis ` +
            `did not run", not "this code is clean" — this says nothing either way about whether ` +
            `the code is vulnerable.`,
          suggestion:
            `Do not treat this run as an injection-class security review. A hosted SECURITY or ` +
            `FULL_AUDIT scan runs the SAST pass over the same code and reports what it finds.`,
          impactScore: 20,
          effort: 'low',
          metadata: {
            sastPassRan: false,
            securityRatio: coverage.securityRatio,
            securityLoc: coverage.securityLoc,
            totalLoc: coverage.totalLoc,
            sastLanguages,
          },
        },
      ]
    }

    // The pass ran, but with a reduced rule set. Naming only what it covered
    // would let a reader infer the rest was checked and clean — the same
    // inference the block above exists to prevent, one level down.
    const unchecked = context.sastUncheckedClasses
    if (context.sast && unchecked && unchecked.length > 0 && coverage.securityLoc >= MIN_ANALYZABLE_LOC) {
      return [
        {
          category: 'SECURITY_HYGIENE',
          severity: 'INFO',
          title: 'Security static analysis ran with a reduced rule set',
          description:
            `The security pass ran on the ${coverage.securityLoc} lines it covers here, including ` +
            `taint tracking from untrusted source to SQL execution. It did NOT check ` +
            `${unchecked.join(', ')}. Those rules need analysis this profile does not perform, so ` +
            `the absence of a finding in those classes means "not checked", not "clean".`,
          suggestion:
            `A hosted SECURITY or FULL_AUDIT scan runs the complete rule pack — every class listed ` +
            `above — over the same code.`,
          impactScore: 20,
          effort: 'low',
          metadata: {
            sastPassRan: true,
            sastUncheckedClasses: [...unchecked],
            securityLoc: coverage.securityLoc,
            totalLoc: coverage.totalLoc,
          },
        },
      ]
    }

    if (coverage.securityLimited) {
      const lang =
        coverage.primaryLanguage ?? coverage.structureOnlyLanguages[0] ?? 'this language'
      return [
        {
          category: 'SECURITY_HYGIENE',
          severity: 'INFO',
          title: `Security coverage is partial for ${lang}`,
          description:
            `Structure and complexity for ${lang} are fully analyzed via AST parsing — the ` +
            `architecture, call-graph and health scores reflect the real code. Security coverage ` +
            `is partial, not absent: CodeTruss ran secret scanning plus the pattern and dataflow ` +
            `rules that apply to ${lang}, but its untrusted-input catalog is tuned for TypeScript, ` +
            `JavaScript and Python, so injection and deserialization coverage for ${lang} is ` +
            `narrower than for those languages. Read the security score as "nothing found by the ` +
            `checks that ran", not "this code is secure".`,
          suggestion:
            `Treat the security score for ${lang} as partial coverage. A manual security review ` +
            `is still warranted for injection, untrusted input and deserialization.`,
          impactScore: 20,
          effort: 'low',
          metadata: {
            structureRatio: coverage.structureRatio,
            securityRatio: coverage.securityRatio,
            securityLoc: coverage.securityLoc,
            totalLoc: coverage.totalLoc,
            structureOnlyLanguages: coverage.structureOnlyLanguages,
          },
        },
      ]
    }

    return []
  },
}
