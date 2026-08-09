import type { AnalyzerFinding, AnalyzerPass, RepoIndex, Scores } from '@codetruss/analyzer-engine'

export type Verdict = 'PASS' | 'REVIEW_REQUIRED' | 'FAILED'
/**
 * `inferred` is in scope on weaker evidence than `allowed`: the repository
 * approved nothing that covers the path, but this turn's own task text and
 * changed files did. It is always disclosed on the receipt, never silent.
 */
export type ScopeClassification = 'allowed' | 'denied' | 'unexpected' | 'inferred'
/** In descending trust order; see packages/cli/src/scope-inference.ts. */
export const INFERRED_SCOPE_BASES = ['task-reference', 'working-set', 'sibling-test'] as const
export type InferredScopeBasis = typeof INFERRED_SCOPE_BASES[number]

export interface InferredScopeRoot {
  /** Repository-relative directory, or a single file for `sibling-test`. */
  root: string
  basis: InferredScopeBasis
  /** What this allowance was read from: the task phrase, or the changed paths. */
  evidence: string[]
}
export const RECEIPT_INVOCATION_KINDS = ['manual_run', 'manual_review', 'pre_commit', 'agent_hook'] as const
export type ReceiptInvocationKind = typeof RECEIPT_INVOCATION_KINDS[number]
export const AGENT_HOOK_SURFACES = ['claude', 'codex'] as const
export type AgentHookReceiptSurface = typeof AGENT_HOOK_SURFACES[number]
export const LLM_PROVIDERS = ['anthropic', 'openai', 'claude'] as const
export type LlmProvider = typeof LLM_PROVIDERS[number]
/** `codex` remains readable so pre-0.2 repository config does not break deterministic commands. */
export const CONFIG_LLM_PROVIDERS = [...LLM_PROVIDERS, 'codex'] as const
export type ConfiguredLlmProvider = typeof CONFIG_LLM_PROVIDERS[number]
export const MAX_LLM_DIFF_BYTES = 2_000_000

/**
 * Honest local-analysis contract: which passes ran on this machine, which did
 * not, and whether scores may be inferred.
 *
 * `local-registry-v5` supersedes `local-registry-v4`. The pass SET is identical
 * again, but v4's SQL bullet says CWE-89 means "untrusted input tracked from
 * request sources through string building into query execution", and since
 * 0.2.53 that is not the whole of what the rule reports: a query whose entire
 * text is a caller-supplied parameter is reported too, at HIGH, with no request
 * source behind it. A receipt that under-describes what its own pass can say is
 * the failure this block exists to prevent, so the wording changed and the id
 * changed with it.
 *
 * `local-registry-v4` had superseded `local-registry-v3`. The pass SET is identical
 * — fifteen registry analyzers, the local security pass, no graph — but v3's
 * block states flatly that the local pass "covers JavaScript, TypeScript and
 * TSX only" and that Python "received no security rule or taint analysis". With
 * an installed grammar pack that sentence is false, so the wording had to change
 * and therefore the id had to change with it. v4 renders its Python paragraph
 * from what the run recorded rather than from a constant.
 *
 * `local-registry-v3` had superseded `v2`, which ran thirteen registry
 * analyzers; `v2` had superseded `v1`, in which SAST was omitted entirely.
 *
 * The id is bumped rather than the wording quietly changed, and it is bumped
 * for a count as readily as for a pass: this shape sits inside signed receipts,
 * the profile block is the part that says what did and did not run, and a
 * receipt must keep verifying byte-for-byte against the wording it was signed
 * with. Every superseded version keeps a frozen renderer in `receipt.ts`.
 */
export const LOCAL_ANALYSIS_PROFILE = {
  id: 'local-registry-v5',
  omittedPasses: ['graph'],
  localPasses: ['local-sast'],
  scoreStatus: 'not-computed',
} as const
export type LocalAnalysisProfile = typeof LOCAL_ANALYSIS_PROFILE

/** The v1 shape, retained so receipts signed by CLI ≤ 0.2.34 still parse. */
export interface LegacyLocalAnalysisProfileV1 {
  id: 'local-registry-v1'
  omittedPasses: readonly ['graph', 'sast']
  scoreStatus: 'not-computed'
}
/** The v2 shape, retained so thirteen-analyzer receipts still parse. */
export interface LegacyLocalAnalysisProfileV2 {
  id: 'local-registry-v2'
  omittedPasses: readonly ['graph']
  localPasses: readonly ['local-sast']
  scoreStatus: 'not-computed'
}
/** The v3 shape, retained so JS-only-local-SAST receipts still parse. */
export interface LegacyLocalAnalysisProfileV3 {
  id: 'local-registry-v3'
  omittedPasses: readonly ['graph']
  localPasses: readonly ['local-sast']
  scoreStatus: 'not-computed'
}
/** The v4 shape, retained so request-source-only-SQL receipts still parse. */
export interface LegacyLocalAnalysisProfileV4 {
  id: 'local-registry-v4'
  omittedPasses: readonly ['graph']
  localPasses: readonly ['local-sast']
  scoreStatus: 'not-computed'
}
export type AnyLocalAnalysisProfile =
  | LocalAnalysisProfile
  | LegacyLocalAnalysisProfileV1
  | LegacyLocalAnalysisProfileV2
  | LegacyLocalAnalysisProfileV3
  | LegacyLocalAnalysisProfileV4

export interface CliConfig {
  version: 1
  allow: string[]
  deny: string[]
  /**
   * Globs whose files are kept out of the analysis index entirely.
   *
   * The escape hatch for a file this tool cannot read — a grammar we do not
   * have, a generated blob, a vendored payload our heuristics miss — so a
   * coverage gap does not have to sit on every receipt forever. It is an
   * ANALYSIS exclusion only: an excluded path is still inventoried as a changed
   * file, still classified against allow/deny, still counted as a sensitive
   * surface, and is named on the receipt. Hiding a change would be a worse bug
   * than the coverage gap it works around.
   */
  exclude: string[]
  verify: string[]
  receipts: { dir: string }
  llm: {
    provider?: ConfiguredLlmProvider
    model?: string
    maxDiffBytes: number
  }
  /**
   * Pinned signer identities. A repository is worked on by more than one
   * developer, so the pin is a SET: `publicKeys` lists every trusted signer and
   * `publicKey` is its first entry, kept for the single-signer config shape and
   * for the hook turn context.
   */
  signing: { publicKey?: string; publicKeys: string[] }
  sync: { url: string }
}

export interface SyncEnvelope {
  signedReceipt: string
  signature: string
}

export interface ChangedFile {
  path: string
  oldPath?: string
  change: 'added' | 'modified' | 'deleted' | 'renamed'
  classification: ScopeClassification
  sensitive?: string
  dependency: boolean
  additions: number
  deletions: number
}

export interface VerificationResult {
  command: string
  exitCode: number
  durationMs: number
  output: string
  truncated: boolean
}

export interface LlmReview {
  provider: string
  model?: string
  transmittedBytes: number
  /** Optional only so receipts issued before this coverage field was introduced remain verifiable. */
  diffCoverage?: {
    totalBytes: number
    reviewedBytes: number
    truncated: boolean
  }
  verdict: 'clean' | 'review'
  summary: string
  findings: string[]
}

interface AnalyzerReceiptEvidence {
  passes: AnalyzerPass[]
  /** Only findings introduced or worsened between the reviewed snapshots, minus any dismissed inline. */
  findings: AnalyzerFinding[]
  /**
   * Findings dismissed by an inline `codetruss-ignore: <reason>` comment, each
   * carrying the reason given. Whole-repository, not delta-scoped, and present
   * only when this repository dismissed something — which is what keeps every
   * receipt signed before suppression existed rendering byte for byte.
   */
  suppressed?: AnalyzerFinding[]
  /**
   * `path:line` of markers that gave no reason and therefore dismissed nothing.
   * Their findings stay in `findings`; this exists so a comment is never seen to
   * fail in silence.
   */
  rejectedSuppressions?: string[]
  delta?: { introduced: number; worsened: number; recurring: number; resolved: number }
  index: Pick<RepoIndex, 'totalLoc' | 'languages' | 'primaryLanguage'>
}

export type AnalyzerReceipt = AnalyzerReceiptEvidence & (
  | {
      /** Current local receipts never infer hosted Health scores from an incomplete pass set. */
      analysisProfile: AnyLocalAnalysisProfile
      scores?: never
      baselineScores?: never
    }
  | {
      /** Compatibility shape for signed receipt-v1 files written by earlier CLI versions. */
      analysisProfile?: never
      scores: Scores
      baselineScores?: Scores
    }
)

export interface Receipt {
  receiptVersion: 1
  sessionId: string
  createdAt: string
  finishedAt: string
  durationMs: number
  mode: 'run' | 'review'
  /**
   * How this receipt was invoked. Optional only for signed receipt-v1 files
   * issued before provenance was introduced; every current receipt includes it.
  */
  invocation?:
    | { kind: 'manual_run' | 'manual_review'; provenance: 'direct'; cliVersion: string }
    | { kind: 'pre_commit'; provenance: 'self_attested'; cliVersion: string }
    | { kind: 'agent_hook'; provenance: 'hook_context'; surface: AgentHookReceiptSurface; cliVersion: string }
  task: string
  repoRoot: string
  startCommit: string
  endCommit: string
  /** Immutable Git trees that produced every file, diff, analyzer, and verification fact. Present on current receipts; omitted by early v1 clients. */
  git?: { baselineTree: string; finalTree: string }
  /** Stable digest of effective scope, verification, and optional LLM policy. Present on current receipts; omitted by early v1 clients. */
  policy?: { sha256: string }
  startDirty: boolean
  startDirtyFiles: string[]
  agent?: { command: string[]; exitCode: number; durationMs: number; startError?: string }
  /**
   * `allow`/`deny` are the approved policy. `inferred` records the weaker,
   * turn-only allowances that covered paths the policy did not, and is present
   * only when this turn actually used one — which is what keeps receipts signed
   * before inference existed rendering, and verifying, byte for byte.
   */
  scope: { allow: string[]; deny: string[]; exclude?: string[]; inferred?: InferredScopeRoot[] }
  files: ChangedFile[]
  diff: { sha256: string; bytes: number; totalBytes?: number; truncated: boolean }
  analyzers: AnalyzerReceipt
  verifications: VerificationResult[]
  llm?: LlmReview
  coverageNotes: string[]
  verdict: Verdict
  reasons: string[]
  /** `exporter` appears only on hosted-sync copies: the key that signed the
   * sync envelope, kept separate so exporting a teammate's receipt can never
   * relabel who produced it (`publicKey`/`keyFingerprint` stay the producer's). */
  evidence: { markdownSha256?: string; patchFile?: string; patchSha256?: string; signatureFile?: string; publicKey?: string; keyFingerprint?: string; exporter?: { publicKey: string; keyFingerprint: string } }
}

export interface ReviewOptions {
  mode: 'run' | 'review'
  task: string
  allow: string[]
  deny: string[]
  exclude: string[]
  verify: string[]
  llm: boolean
  provider?: string
  staged: boolean
  agentCommand?: string[]
}
