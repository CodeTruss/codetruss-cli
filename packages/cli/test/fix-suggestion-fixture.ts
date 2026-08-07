import { createHash } from 'node:crypto'
import type { AnalyzerFinding } from '@codetruss/analyzer-engine'
import type { Receipt } from '../src/types.js'

/**
 * A fully-determined receipt: every field that reaches the Markdown renderer is
 * fixed, so its rendering is a stable golden. Shared by the fix-suggestion tests
 * and by the throwaway script that captured the pre-suggestion golden bytes.
 */
export function fixtureReceipt(findings: AnalyzerFinding[] = []): Receipt {
  const patch = 'diff evidence'
  return {
    receiptVersion: 1,
    sessionId: '20260712T210000123Z-fixture',
    createdAt: '2026-07-12T21:00:00.123Z',
    finishedAt: '2026-07-12T21:00:00.123Z',
    durationMs: 0,
    mode: 'review',
    task: 'fix suggestion fixture',
    repoRoot: '/repo',
    startCommit: 'abc',
    endCommit: 'abc',
    git: { baselineTree: 'a'.repeat(40), finalTree: 'b'.repeat(40) },
    policy: { sha256: 'c'.repeat(64) },
    startDirty: false,
    startDirtyFiles: [],
    scope: { allow: ['src/**'], deny: [] },
    files: [],
    diff: {
      sha256: createHash('sha256').update(patch).digest('hex'),
      bytes: Buffer.byteLength(patch),
      totalBytes: Buffer.byteLength(patch),
      truncated: false,
    },
    analyzers: {
      passes: [],
      findings,
      // Pinned to v1, not to whatever LOCAL_ANALYSIS_PROFILE currently is: the
      // golden below captures bytes CLI 0.2.30 actually wrote, and the receipts
      // already signed on disk are v1 receipts. Tracking the current profile
      // would make this assert that today's renderer matches itself, which is
      // not the backward-compatibility claim being made.
      analysisProfile: { id: 'local-registry-v1', omittedPasses: ['graph', 'sast'], scoreStatus: 'not-computed' },
      index: { totalLoc: 0, languages: {}, primaryLanguage: null },
    },
    verifications: [],
    coverageNotes: ['local'],
    verdict: 'REVIEW_REQUIRED',
    reasons: ['1 medium-or-higher analyzer finding(s) affect changed files'],
    evidence: {},
  }
}

/**
 * `renderMarkdown(fixtureReceipt(fixtureFindings()))` as CLI 0.2.30 wrote it —
 * captured by running the pre-suggestion renderer, not by re-recording current
 * output. Fix suggestions must stay purely additive: a receipt whose findings
 * carry no fix has to render to these exact bytes, or every receipt already
 * signed on disk stops verifying.
 */
export const PRE_SUGGESTION_RECEIPT_MARKDOWN = "# CodeTruss receipt — REVIEW_REQUIRED\n\n- **Session:** `20260712T210000123Z-fixture`\n- **Task:** fix suggestion fixture\n- **Repository:** `/repo`\n- **Starting commit:** `abc`\n- **Evidence trees:** `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` → `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`\n- **Policy SHA-256:** `cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`\n- **Mode:** review\n\n## Verdict: REVIEW_REQUIRED\n\n- 1 medium-or-higher analyzer finding(s) affect changed files\n\nDiff evidence: 13/13 bytes captured (complete), SHA-256 `7d9ef774aece6330…`.\n\n## Changed files (0)\n\n| Path | Change | Scope | Sensitive | Lines |\n|---|---|---|---|---:|\n\n## Introduced or worsened analyzer findings (2)\n\n| Severity | Analyzer | Location | Finding |\n|---|---|---|---|\n| HIGH | secrets | `src/config.ts:12` | Possible AWS access key committed in config.ts |\n| MEDIUM | dependencies | repository | No lockfile committed |\n\n## Analysis profile\n\nProfile: `local-registry-v1`.\n\nThe 13 deterministic registry analyzers ran locally on this machine.\n\n### What did not run\n\n- **Security static analysis (SAST).** No injection or taint analysis was performed. SQL injection, command injection, code injection, path traversal, SSRF, open redirect, XSS and insecure deserialization were never checked, so this receipt says nothing either way about those classes.\n- **Hosted symbol graph.** No cross-file call or data-flow graph was built, so architecture and dead-code conclusions cover only what the local passes can see in isolation.\n- **Optional LLM review.** No model read this diff. It is opt-in via `--llm` and is force-disabled under agent hooks, so a hook receipt is always deterministic evidence only.\n- **Hosted Health scores.** Not calculated, reported as **N/A**. The scores are defined over the graph and SAST passes; a number derived from this pass set would overstate what ran.\n\nA PASS verdict means the passes listed above never ran and the passes that did run found nothing new. It is not a statement that this change is secure.\n\n[Run a hosted full audit](https://codetruss.com/dashboard/repos/new?source=cli-receipt).\n\n## Verification\n\n- No verification commands configured.\n\n## Coverage and privacy\n\n- local\n\n_The signature proves these receipt bytes have not changed since signing. It does not prove trusted execution or that every analysis conclusion is correct._\n"

/** One finding of each kind the renderer has to handle, without any fix. */
export function fixtureFindings(): AnalyzerFinding[] {
  return [
    {
      category: 'SECURITY_HYGIENE',
      severity: 'HIGH',
      title: 'Possible AWS access key committed in config.ts',
      description: 'Line 12 of src/config.ts appears to contain an AWS access key.',
      filePath: 'src/config.ts',
      line: 12,
      suggestion: 'Rotate this credential immediately.',
      impactScore: 95,
      effort: 'low',
      analyzerId: 'secrets',
    },
    {
      category: 'DEPENDENCY',
      severity: 'MEDIUM',
      title: 'No lockfile committed',
      description: 'package.json exists but no lockfile is committed.',
      suggestion: 'Commit the lockfile for your package manager.',
      impactScore: 75,
      effort: 'low',
      analyzerId: 'dependencies',
    },
  ]
}
