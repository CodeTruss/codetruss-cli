import { CWE, type CweInfo } from './cwe'
import { PATTERN_RULES, TAINT_SINKS } from './rules'

/**
 * What the SAST engine's security verdict does — and does not — cover.
 *
 * A security score computed over the classes the engine can see must never be
 * read as a verdict over the classes it cannot. This module is the single
 * source of truth for both lists: the analyzed classes are DERIVED from the
 * live rule pack (they cannot drift from reality), and the not-analyzed list
 * is curated with a sync-guard test (tests/scoring.test.ts) that forces an
 * entry out the moment a rule for its class ships.
 */

/** Vulnerability classes with rule-backed analysis, derived from the rule pack. */
export function analyzedVulnerabilityClasses(): CweInfo[] {
  const keys = new Set<string>()
  for (const rule of TAINT_SINKS) keys.add(rule.cweKey)
  for (const rule of PATTERN_RULES) keys.add(rule.cweKey)
  return [...keys].map((key) => CWE[key]).sort((a, b) => a.title.localeCompare(b.title))
}

export interface UnanalyzedClass {
  name: string
  /** CWE id when one exists — feeds the no-overlap sync guard. */
  cwe?: string
  /** One sentence on why this needs eyes, phrased for a report reader. */
  detail: string
}

/**
 * Classes a syntactic rule/taint engine structurally cannot judge. These need
 * a human review (or a future analysis the engine does not have yet) — the
 * report says so explicitly instead of letting a green score imply them.
 */
export const UNANALYZED_VULNERABILITY_CLASSES: UnanalyzedClass[] = [
  {
    name: 'Authorization & tenant isolation (IDOR)',
    cwe: 'CWE-639',
    detail:
      'whether each endpoint verifies the caller may access the specific resource it names — this requires understanding your permission model, not just the code',
  },
  {
    name: 'Authentication & session management logic',
    cwe: 'CWE-287',
    detail: 'correctness of login flows, token lifetimes, session fixation and revocation',
  },
  {
    name: 'Cross-site scripting (XSS) — partially analyzed',
    cwe: 'CWE-79',
    detail:
      'tainted dangerouslySetInnerHTML / innerHTML / outerHTML assignments ARE analyzed in JavaScript, TypeScript and TSX; server-side template engines, hand-built HTML strings and non-JS languages are not',
  },
  {
    name: 'Cross-site request forgery (CSRF)',
    cwe: 'CWE-352',
    detail: 'presence and correctness of anti-CSRF protections on state-changing routes',
  },
  {
    name: 'Webhook & callback signature verification',
    cwe: 'CWE-347',
    detail: 'whether inbound webhooks verify their signatures before acting on the payload',
  },
  {
    name: 'Business-logic flaws',
    cwe: 'CWE-840',
    detail: 'price manipulation, workflow bypass, quantity and limit abuse',
  },
  {
    name: 'Race conditions — partially analyzed',
    cwe: 'CWE-367',
    detail:
      'unguarded read-modify-write pairs — a row read, recomputed arithmetically, and written back outside a transaction — ARE analyzed in JavaScript, TypeScript and TSX; check-then-act windows (validate then insert, existence check before a write, multi-request state machines) are not',
  },
  {
    name: 'Infrastructure & deployment configuration',
    detail: 'cloud IAM, network policy and runtime hardening living outside this repository',
  },
]
