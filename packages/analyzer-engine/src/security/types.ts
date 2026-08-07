/**
 * SAST engine public types.
 *
 * A finding is trustworthy only when it can show *why*: the source of the
 * untrusted value, the sink it reached, and the path between them. Every taint
 * finding carries a {@link Flow}; pattern findings (dangerous API / insecure
 * config) carry only the sink site because there is no dataflow to show.
 */

import type { SastLanguage } from './lang'

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

/** How a finding was proven — dataflow vs. a dangerous API/config match. */
export type FindingKind = 'taint' | 'pattern'

export interface CodeLocation {
  filePath: string
  line: number
  /** 1-based column, best effort. */
  column?: number
  /** A short, single-line snippet of the offending code (never secrets/values). */
  snippet?: string
}

/**
 * The proof for a taint finding: where the untrusted value entered, where it
 * landed, and a human-readable summary of the hops between them. `steps`
 * includes source and sink as the first and last entries.
 */
export interface Flow {
  source: CodeLocation & { label: string }
  sink: CodeLocation & { label: string }
  steps: Array<CodeLocation & { label: string }>
  /** One-line English summary, e.g. "req.query.id → id → db.query()". */
  summary: string
  /** True when the value crossed a function boundary (one-hop interprocedural). */
  interprocedural: boolean
}

export interface SastFinding {
  ruleId: string
  kind: FindingKind
  /** e.g. "CWE-89". */
  cwe: string
  /** e.g. "A03:2021 Injection". */
  owasp: string
  severity: Severity
  /** Short, specific human-readable title. */
  title: string
  /** Longer explanation of the risk and why this instance is flagged. */
  message: string
  language: SastLanguage
  filePath: string
  line: number
  column?: number
  /** Present for taint findings; absent for pattern findings. */
  flow?: Flow
  /** Remediation guidance. */
  remediation: string
  /** Stable, sorted metadata for the report layer. */
  metadata?: Record<string, unknown>
}

/** Per-scan diagnostics so callers can be honest about coverage. */
export interface SastDiagnostics {
  /** Files handed to the engine after production/test filtering. */
  inputFiles: number
  filesScanned: number
  filesSkipped: number
  /** Languages that could not be parsed (grammar unavailable) — SAST degraded. */
  degradedLanguages: SastLanguage[]
  /** Files whose scan hit the per-file budget and returned partial results. */
  truncatedFiles: number
  /**
   * Files the per-file WALL-CLOCK ceiling cut short. Also counted in
   * {@link truncatedFiles} — it is the same coverage loss as the node budget —
   * so every consumer that already handles truncation handles this too.
   */
  timeCappedFiles?: number
  /** Paths of those files, so a report can NAME them and not only count them.
   *  Bounded; {@link timeCappedFiles} stays authoritative for the total. */
  timeCappedPaths?: string[]
  /**
   * Files never analyzed at all because the whole-pass wall-clock ceiling was
   * reached first. Also counted in {@link filesSkipped}.
   */
  timeSkippedFiles?: number
  /** Paths of those files, bounded the same way. */
  timeSkippedPaths?: string[]
  /** The global finding cap was reached and later findings were omitted. */
  findingsTruncated: boolean
  /** A process resource bound stopped a batch before every file was scanned. */
  resourceLimitReached?: boolean
  /** A wall-clock ceiling stopped the scan before every file was analyzed —
   *  either the engine's own pass ceiling or the isolated runner's job limit. */
  budgetExceeded?: boolean
  /** A systemic child-runtime failure stopped later batches from starting. */
  failureReason?: string
}

export interface SastResult {
  findings: SastFinding[]
  diagnostics: SastDiagnostics
}
