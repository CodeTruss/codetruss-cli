import type { AnalyzerFinding } from './types'
import type { RepoIndex } from './types'
import { analysisCoverage } from './coverage'

export interface Scores {
  health: number
  debt: number
  architecture: number
  security: number
  docs: number
}

/**
 * Per-finding severity weights. CRITICAL is weighted far above the rest on
 * purpose: two committed credentials should roughly halve an axis, while a
 * pile of LOW/MEDIUM findings on a sizable codebase should dent it, not
 * flatten it (the old linear deduction scored a 10k-LOC repo full of LOWs
 * at 5/100).
 */
const SEVERITY_WEIGHT = { CRITICAL: 60, HIGH: 8, MEDIUM: 3, LOW: 1, INFO: 0.25 } as const

/** Compression constant: score = 100 * exp(-weight / K). */
const K = 165
/** LOC baseline for size normalization of non-critical findings. */
const BASELINE_LOC = 10_000

/**
 * What rule produced a finding. SAST carries a `ruleId` and the secrets pass a
 * `credentialType`; everything else is identified by its title, which is stable
 * per rule per file (the file name it may embed does not vary within a file).
 */
function ruleKey(f: AnalyzerFinding): string {
  const meta = f.metadata as Record<string, unknown> | undefined
  const rule =
    (typeof meta?.ruleId === 'string' && meta.ruleId)
    || (typeof meta?.credentialType === 'string' && meta.credentialType)
    || f.title
  return `${f.analyzerId ?? ''}\u0000${rule}`
}

/**
 * One line, one price — even when two passes found it.
 *
 * A hard-coded credential in a doc comment is reported by the regex secrets
 * analyzer AND by the SAST `Hard-coded credential` rule, and the score charged
 * for both. That is one review decision and one edit. The finding LIST keeps
 * both entries, because each carries different evidence and a different fix;
 * only the arithmetic collapses them.
 *
 * Cost: two genuinely distinct defects on one line (an injection and an XSS in
 * the same expression) are priced as one. Lines that dense are rare, and the
 * remediation is a single edit either way.
 */
function dedupeByLocation(findings: AnalyzerFinding[]): AnalyzerFinding[] {
  const bySite = new Map<string, AnalyzerFinding>()
  const out: AnalyzerFinding[] = []
  for (const f of findings) {
    if (!f.filePath || f.line === undefined) {
      out.push(f)
      continue
    }
    const site = `${f.filePath}:${f.line}`
    const held = bySite.get(site)
    if (!held) {
      bySite.set(site, f)
      continue
    }
    // Keep the worst: a CRITICAL must never be displaced by a LOW that merely
    // arrived first.
    if (SEVERITY_WEIGHT[f.severity] > SEVERITY_WEIGHT[held.severity]) bySite.set(site, f)
  }
  return out.concat([...bySite.values()])
}

/**
 * Repeat hits of the SAME rule in the SAME file decay logarithmically: a group
 * of n costs `1 + ln(n)` findings, not n.
 *
 * Eight firings of one regex against one mock string in one spec file was 64
 * weight — 14% of a 300k-LOC repository's entire security deduction — for a
 * single review decision. The first (worst) finding in a group is charged in
 * full and each repeat adds a diminishing increment, so a group containing a
 * CRITICAL still costs at least that CRITICAL.
 *
 * Cost, and it is real: a file with twelve DISTINCT injection sinks now prices
 * close to a file with one. Concentration is legitimate signal and most of it
 * is lost here. The trade was made because concentrated FALSE positives were
 * measurably more common than concentrated true ones — but a reviewer reading
 * only the score will not see the difference, and the finding list is where
 * that density remains visible.
 */
function occurrenceFactor(rank: number): number {
  return rank === 0 ? 1 : Math.log((rank + 1) / rank)
}

function deduct(findings: AnalyzerFinding[], categories: string[], totalLoc: number): number {
  const relevant = dedupeByLocation(findings.filter((f) => categories.includes(f.category)))
  const groups = new Map<string, AnalyzerFinding[]>()
  const ungrouped: AnalyzerFinding[] = []
  for (const f of relevant) {
    if (!f.filePath) {
      ungrouped.push(f)
      continue
    }
    const key = `${ruleKey(f)}\u0000${f.filePath}`
    const group = groups.get(key)
    if (group) group.push(f)
    else groups.set(key, [f])
  }

  let fixedWeight = 0
  let scaledWeight = 0
  const charge = (f: AnalyzerFinding, factor: number): void => {
    const w = SEVERITY_WEIGHT[f.severity] * factor
    if (f.severity === 'CRITICAL' || f.severity === 'HIGH') fixedWeight += w
    else scaledWeight += w
  }
  for (const f of ungrouped) charge(f, 1)
  for (const group of groups.values()) {
    group.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity])
    group.forEach((f, rank) => charge(f, occurrenceFactor(rank)))
  }
  // Volume-driven findings (LOW/MEDIUM) are normalized by codebase size:
  // 30 LOWs mean something different at 100k LOC than at 5k. CRITICALs and
  // HIGHs never dilute — a leaked key or vulnerable dependency is just as
  // severe regardless of repo size.
  const sizeFactor = Math.sqrt(Math.max(totalLoc, BASELINE_LOC) / BASELINE_LOC)
  const weight = fixedWeight + scaledWeight / sizeFactor
  // Exponential compression: diminishing returns per extra finding, never
  // collapses to a meaningless floor, spreads scores across the range.
  return Math.round(100 * Math.exp(-weight / K))
}

/**
 * Neutral "we don't know" midpoint. When deep analysis didn't run for most of a
 * repo, the graph-dependent axes decay toward this instead of a confident 100.
 * 50, not 0: withholding an unearned high score is honest; slamming to zero
 * would be dishonest in the other direction.
 */
const NEUTRAL_SCORE = 50

/** Deterministic 0-100 scores derived from findings + repo shape. */
export function computeScores(index: RepoIndex, allFindings: AnalyzerFinding[]): Scores {
  // A finding a developer dismissed with a reasoned `codetruss-ignore` marker
  // stays on every report as evidence — but it stops scoring, for the same
  // reason it already stops gating the CLI verdict: that is what dismissing it
  // is for. Charging for it anyway scored this product's own repository 32 on
  // Security over its own annotated acceptance fixtures — planted, reasoned,
  // and disclosed on every receipt, yet priced like leaks. Markers without a
  // reason never applied in the first place (suppression.ts) and still charge.
  const findings = allFindings.filter((f) => !f.suppression?.applied)
  const loc = index.totalLoc
  const debt = deduct(findings, ['TECH_DEBT', 'DUPLICATION', 'DEAD_CODE'], loc)
  let security = deduct(findings, ['SECURITY_HYGIENE', 'DEPENDENCY'], loc)
  const docs = deduct(findings, ['DOCUMENTATION'], loc)
  let architecture = deduct(findings, ['STRUCTURE', 'ARCHITECTURE', 'TESTING'], loc)

  // Analysis coverage caps each axis to the depth we actually reached, along two
  // independent axes. A cap is a min(): it never RAISES a score, so genuine
  // surface problems still show through — it only withholds a high score we
  // didn't earn. Each ceiling decays to NEUTRAL_SCORE as its coverage → 0.
  //
  //   STRUCTURE (architecture + health): deep for native TS/JS/Python AND for
  //   tree-sitter languages (C#, Go, Java, Rust, PHP, Ruby) — we extract real
  //   symbols, call-graph and complexity. So a well-structured C# repo can score
  //   architecture 85+ on its merits and a messy one scores low; the cap applies
  //   ONLY when the repo is mostly a language with no structural analysis at all.
  //
  //   SECURITY: the SAST engine (rules + taint tracking) runs for the languages
  //   it covers (SAST_COVERED_LANGUAGES). For those the security score is EARNED
  //   and UNCAPPED — real taint findings lower it, genuinely clean code scores
  //   high. Tree-sitter-only languages (C#, Go, …) get structure but only a
  //   regex secrets scan for security, NOT injection/untrusted-input analysis. A
  //   100 there tells a client "this code is secure" when it was never security-
  //   analyzed — the single most dangerous false signal an auditor can emit — so
  //   the security cap remains for the languages the SAST engine does NOT cover.
  //
  // Debt and docs stay unchanged: their checks (finding volume, README/license
  // presence) are genuinely language-agnostic.
  const coverage = analysisCoverage(index)
  const structureCeiling = coverage.structureLimited
    ? Math.round(NEUTRAL_SCORE + (100 - NEUTRAL_SCORE) * coverage.structureRatio)
    : null
  const securityCeiling = coverage.securityLimited
    ? Math.round(NEUTRAL_SCORE + (100 - NEUTRAL_SCORE) * coverage.securityRatio)
    : null
  if (structureCeiling !== null) architecture = Math.min(architecture, structureCeiling)
  if (securityCeiling !== null) security = Math.min(security, securityCeiling)

  // Health = weighted blend, biased toward security & debt. The security cap
  // already flows into health through its 0.3 weight, so health only needs an
  // explicit cap for the structure axis (uncertain structure undermines the
  // whole health picture).
  let health = Math.round(
    security * 0.3 + debt * 0.3 + architecture * 0.25 + docs * 0.15,
  )
  if (structureCeiling !== null) health = Math.min(health, structureCeiling)

  return { health, debt, architecture, security, docs }
}
