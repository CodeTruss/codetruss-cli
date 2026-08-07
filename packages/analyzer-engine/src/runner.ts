import { getAnalyzers } from './registry'
import {
  analyzerResult,
  analyzerWithheld,
  REGISTRY_ONLY_ANALYSIS,
  type AnalyzerContext,
  type AnalyzerFinding,
  type AnalyzerRunResult,
  type RepoIndex,
} from './types'

export interface AnalyzerPass {
  id: string
  result: AnalyzerRunResult
  error?: string
}

/**
 * Run every deterministic analyzer without allowing one failed pass to abort the suite.
 *
 * `withheld` collects what each pass found and then dropped to respect its own
 * finding cap. It is never reported or persisted — it exists so a baseline/final
 * comparison can tell "hidden by a cap" apart from "not present", which is the
 * difference between an honest delta and one that blames a change for findings
 * it did not introduce. See `analyzerWithheld` in types.ts.
 */
export async function runAnalyzers(
  index: RepoIndex,
  context: AnalyzerContext = REGISTRY_ONLY_ANALYSIS,
): Promise<{ findings: AnalyzerFinding[]; withheld: AnalyzerFinding[]; passes: AnalyzerPass[] }> {
  const findings: AnalyzerFinding[] = []
  const withheld: AnalyzerFinding[] = []
  const passes: AnalyzerPass[] = []
  for (const analyzer of getAnalyzers()) {
    try {
      const output = await analyzer.run(index, context)
      const raw = analyzerResult(output)
      const result = {
        ...raw,
        findings: raw.findings.map((finding) => ({ ...finding, analyzerId: analyzer.id })),
      }
      findings.push(...result.findings)
      withheld.push(...analyzerWithheld(output).map((finding) => ({ ...finding, analyzerId: analyzer.id })))
      passes.push({ id: analyzer.id, result })
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      passes.push({
        id: analyzer.id,
        result: { findings: [], complete: false, detail },
        error: detail,
      })
    }
  }
  return { findings, withheld, passes }
}
