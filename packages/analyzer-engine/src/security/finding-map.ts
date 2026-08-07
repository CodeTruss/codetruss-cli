import type { AnalyzerFinding, FindingCategory } from '../types'
import type { SastFinding, Severity } from './types'

/**
 * Engine finding → analyzer finding, shared by both front-ends.
 *
 * The hosted pipeline and the CLI must agree on severity weight and category or
 * the same defect would rank differently depending on where it was found, and
 * the receipt would stop matching the audit. This module is the single place
 * that decision lives.
 */

/** Severity → impactScore (drives fix-plan ranking), aligned with other analyzers. */
export const SAST_SEVERITY_IMPACT: Record<Severity | 'INFO', number> = {
  CRITICAL: 95,
  HIGH: 80,
  MEDIUM: 55,
  LOW: 30,
  INFO: 15,
}

/**
 * CWE-1050 (db-call-in-loop / N+1) is a performance defect, not a security one:
 * PERFORMANCE participates in no score axis, so the rule can never deduct the
 * security score while still ranking in fix plans via impactScore and persisting
 * through the finding lifecycle.
 */
export function sastFindingCategory(cwe: string): FindingCategory {
  return cwe === 'CWE-1050' ? 'PERFORMANCE' : 'SECURITY_HYGIENE'
}

/** Pure map: one engine finding → one AnalyzerFinding. */
export function mapSastFinding(finding: SastFinding): AnalyzerFinding {
  const locate = (location: { label: string; filePath: string; line: number }) =>
    `${location.label} (${location.filePath}:${location.line})`
  const flow = finding.flow
    ? {
        source: locate(finding.flow.source),
        sink: locate(finding.flow.sink),
        path: finding.flow.steps.map(locate),
      }
    : {
        // Pattern findings have no dataflow — the sink site IS the finding.
        source: `${finding.title} (${finding.filePath}:${finding.line})`,
        sink: `${finding.title} (${finding.filePath}:${finding.line})`,
        path: [`${finding.filePath}:${finding.line}`],
      }
  return {
    category: sastFindingCategory(finding.cwe),
    severity: finding.severity,
    title: finding.title.slice(0, 140),
    description: finding.message,
    filePath: finding.filePath,
    line: finding.line,
    suggestion: finding.remediation,
    impactScore: SAST_SEVERITY_IMPACT[finding.severity] ?? 50,
    effort: 'medium',
    metadata: {
      // `sast: true` distinguishes real taint findings from regex secret hits
      // in the same category — the report Security section keys off it.
      sast: true,
      cwe: finding.cwe,
      owasp: finding.owasp,
      ruleId: finding.ruleId,
      flow,
    },
  }
}
