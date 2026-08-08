import { incompleteAnalyzerOutput, measuredCoverage, type Analyzer, type AnalyzerFinding } from './types'

const MARKER = /(?:\/\/|#|\/\*|<!--)\s*(TODO|FIXME|HACK|XXX)\b[:\s]?(.{0,120})/

/** Surfaces accumulated TODO/FIXME/HACK markers as trackable debt. */
export const todosAnalyzer: Analyzer = {
  id: 'todos',
  name: 'TODO Tracker',
  description: 'Aggregates TODO, FIXME, and HACK comments into visible technical debt.',
  async run(index) {
    /** Retained markers — the sample the per-marker findings are drawn from. */
    const hits: Array<{ path: string; line: number; kind: string; text: string }> = []

    const hitLimit = 500
    /**
     * Every marker in the tree, counted past the retention bound. The headline
     * finding is a count, so stopping the counter at 500 made it report the
     * bound instead of the codebase — and left the pass unable to say how much
     * of its input it had actually seen.
     */
    let markers = 0
    let fixmeMarkers = 0
    for (const file of index.files) {
      if (!file.content || file.kind === 'doc' || file.kind === 'asset') continue
      const lines = file.content.split('\n')
      for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(MARKER)
        if (!m) continue
        markers++
        if (m[1] === 'FIXME' || m[1] === 'XXX' || m[1] === 'HACK') fixmeMarkers++
        if (hits.length < hitLimit) hits.push({ path: file.path, line: i + 1, kind: m[1], text: m[2].trim() })
      }
    }

    if (markers === 0) return []

    const fixmes = hits.filter((h) => h.kind === 'FIXME' || h.kind === 'XXX' || h.kind === 'HACK')
    const findings: AnalyzerFinding[] = []

    if (markers >= 10) {
      findings.push({
        category: 'TECH_DEBT',
        severity: markers >= 50 ? 'MEDIUM' : 'LOW',
        title: `${markers} TODO/FIXME markers across the codebase`,
        description: `The codebase carries ${markers} deferred-work markers (${fixmeMarkers} FIXME/HACK). Unowned TODOs are debt with no repayment plan.`,
        suggestion: 'Convert real TODOs into tracked issues and delete stale ones.',
        impactScore: Math.min(60, 20 + markers),
        effort: 'medium',
        metadata: { total: markers, sample: hits.slice(0, 20) },
      })
    }

    for (const h of fixmes.slice(0, 5)) {
      findings.push({
        category: 'BUG_RISK',
        severity: 'LOW',
        title: `${h.kind} marker: ${h.text.slice(0, 60) || 'unlabelled'}`,
        description: `${h.path}:${h.line} carries a ${h.kind} marker${h.text ? `: "${h.text}"` : ''}. FIXME/HACK markers usually indicate known-broken behavior.`,
        filePath: h.path,
        line: h.line,
        suggestion: 'Fix the underlying issue or document why the workaround is safe.',
        impactScore: 35,
        effort: 'low',
      })
    }

    // The headline count is exact either way; what the bound costs is the
    // per-marker sample, which is drawn only from the retained markers.
    return markers > hitLimit
      ? incompleteAnalyzerOutput(findings, {
          truncated: true,
          coverageRatio: measuredCoverage(hits.length, markers),
          detail: `TODO analysis retained ${hits.length} of ${markers} markers for per-marker reporting.`,
          metrics: { markers, retained: hits.length, hitLimit },
        })
      : findings
  },
}
