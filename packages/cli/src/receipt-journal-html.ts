import { createHash } from 'node:crypto'
import type { Receipt } from './types.js'

/**
 * The shareable work journal: one self-contained HTML document a client opens
 * in a browser, rendered from signed receipts. The rendering is a VIEW and is
 * unsigned; the evidence is the exact signed receipt JSON and signatures
 * embedded in the document, downloadable and independently verifiable with
 * `codetruss verify-receipt`. This renderer is deliberately separate from
 * receipt-markdown.ts, whose output is frozen byte-for-byte by signatures.
 */

export interface JournalEntry {
  receipt: Receipt
  /** The exact signed receipt JSON bytes, embedded as evidence. */
  signedJson: string
  /** The detached signature over signedJson, base64. */
  signature: string
  /** The receipt's markdown rendering — its digest is inside the signed JSON,
   * so the verifier needs it beside the receipt to establish integrity. */
  markdown: string
}

export interface JournalInput {
  /** Repository basename only — never the absolute path. */
  repo: string
  generatedAt: string
  /** Chronological, oldest first: the journal reads as the story of the work. */
  entries: JournalEntry[]
  /** Receipts present on disk but excluded, and why. Never silently dropped. */
  excluded: { id: string; reason: string }[]
  /** Trusted signer public keys (PEM), offered for download in the appendix. */
  publicKeys: string[]
  includeOutput: boolean
  signature?: { manifest: string; signature: string; fingerprint: string }
}

const VERDICT_LABELS: Record<Receipt['verdict'], string> = {
  PASS: 'Pass',
  REVIEW_REQUIRED: 'Review required',
  FAILED: 'Failed',
}

const INVOCATION_LABELS: Record<string, string> = {
  manual_run: 'agent run',
  manual_review: 'manual review',
  pre_commit: 'pre-commit check',
  agent_hook: 'agent hook',
}

function esc(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function formatDate(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
    timeZone: 'UTC', timeZoneName: 'short',
  })
}

function formatDay(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' })
}

function formatDuration(ms: number): string {
  if (ms < 1_000) return `${ms}ms`
  if (ms < 60_000) return `${Math.round(ms / 1_000)}s`
  return `${Math.round(ms / 60_000)}m`
}

function base64(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64')
}

/** Journal manifest: the canonical statement of what this document contains. */
export function journalManifest(input: Pick<JournalInput, 'repo' | 'generatedAt' | 'entries'>): string {
  return JSON.stringify({
    format: 'codetruss-journal-v1',
    repo: input.repo,
    generatedAt: input.generatedAt,
    receipts: input.entries.map((entry) => ({
      sessionId: entry.receipt.sessionId,
      sha256: sha256(entry.signedJson),
    })),
  })
}

function metricsStrip(input: JournalInput): string {
  const receipts = input.entries.map((entry) => entry.receipt)
  const files = new Set<string>()
  let additions = 0
  let deletions = 0
  let verifications = 0
  let verificationsPassed = 0
  const verdicts: Record<string, number> = {}
  for (const receipt of receipts) {
    for (const file of receipt.files) {
      files.add(file.path)
      additions += file.additions
      deletions += file.deletions
    }
    verifications += receipt.verifications.length
    verificationsPassed += receipt.verifications.filter((item) => item.exitCode === 0).length
    verdicts[receipt.verdict] = (verdicts[receipt.verdict] ?? 0) + 1
  }
  const cell = (label: string, value: string, sub = '') => `
      <div class="metric"><div class="metric-label">${esc(label)}</div><div class="metric-value">${value}${sub ? `<span class="metric-sub">${esc(sub)}</span>` : ''}</div></div>`
  const verdictSummary = (['PASS', 'REVIEW_REQUIRED', 'FAILED'] as const)
    .filter((verdict) => verdicts[verdict])
    .map((verdict) => `${verdicts[verdict]} ${VERDICT_LABELS[verdict].toLowerCase()}`)
    .join(' · ') || 'none'
  return `
    <div class="metrics">
      ${cell('Sessions', String(receipts.length))}
      ${cell('Files touched', String(files.size))}
      ${cell('Lines', `<span class="add">+${additions}</span> <span class="del">−${deletions}</span>`)}
      ${cell('Verifications', `${verificationsPassed}/${verifications}`, 'passed')}
      ${cell('Verdicts', esc(verdictSummary))}
    </div>`
}

function entrySection(entry: JournalEntry, index: number, includeOutput: boolean): string {
  const receipt = entry.receipt
  const invocation = receipt.invocation ? INVOCATION_LABELS[receipt.invocation.kind] ?? receipt.invocation.kind : 'session'
  const files = receipt.files.map((file) => `
        <tr><td class="mono">${esc(file.path)}${file.oldPath ? ` <span class="faint">(from ${esc(file.oldPath)})</span>` : ''}</td><td>${esc(file.change)}</td><td class="num"><span class="add">+${file.additions}</span> <span class="del">−${file.deletions}</span></td></tr>`).join('')
  const verifications = receipt.verifications.length ? `
      <table class="rows">
        <thead><tr><th>Verification</th><th>Result</th><th>Time</th></tr></thead>
        <tbody>${receipt.verifications.map((item) => `
          <tr><td class="mono">${esc(item.command)}</td><td>${item.exitCode === 0 ? '<span class="ok">passed</span>' : `<span class="bad">exit ${item.exitCode}</span>`}</td><td class="num">${formatDuration(item.durationMs)}</td></tr>${includeOutput && item.output ? `
          <tr><td colspan="3"><pre class="output">${esc(item.output)}</pre></td></tr>` : ''}`).join('')}
        </tbody>
      </table>` : '<p class="faint">No verification commands ran in this session.</p>'
  const findings = receipt.analyzers.findings.length ? `
      <ul class="findings">${receipt.analyzers.findings.map((finding) => `
        <li><span class="severity sev-${esc(finding.severity.toLowerCase())}">${esc(finding.severity.toLowerCase())}</span> ${esc(finding.title)}${finding.filePath ? ` <span class="mono faint">${esc(finding.filePath)}${finding.line ? `:${finding.line}` : ''}</span>` : ''}</li>`).join('')}
      </ul>` : ''
  const suppressed = receipt.analyzers.suppressed?.length
    ? `<p class="faint">${receipt.analyzers.suppressed.length} finding(s) were dismissed in source with a written reason; the dismissals travel inside the signed receipt.</p>`
    : ''
  const llm = receipt.llm ? `
      <p class="ai-review"><span class="label">AI review (${esc(receipt.llm.provider)}${receipt.llm.model ? ` · ${esc(receipt.llm.model)}` : ''})</span> ${esc(receipt.llm.summary)}</p>` : ''
  return `
    <section class="entry">
      <header>
        <div class="entry-meta"><span class="entry-index">${String(index + 1).padStart(2, '0')}</span> ${esc(formatDate(receipt.createdAt))} · ${esc(invocation)} · ${esc(formatDuration(receipt.durationMs))}</div>
        <span class="verdict verdict-${esc(receipt.verdict.toLowerCase())}">${VERDICT_LABELS[receipt.verdict]}</span>
      </header>
      <h3>${esc(receipt.task)}</h3>
      <table class="rows">
        <thead><tr><th>File</th><th>Change</th><th>Lines</th></tr></thead>
        <tbody>${files || '<tr><td colspan="3" class="faint">No files changed.</td></tr>'}</tbody>
      </table>
      ${verifications}
      ${findings}
      ${suppressed}
      ${llm}
      <footer class="entry-footer mono">session ${esc(receipt.sessionId)} · signed by ${esc(receipt.evidence.keyFingerprint ?? 'unknown')}</footer>
    </section>`
}

function evidenceAppendix(input: JournalInput): string {
  const rows = input.entries.map((entry) => `
        <tr>
          <td class="mono">${esc(entry.receipt.sessionId)}</td>
          <td class="mono sha">${esc(sha256(entry.signedJson))}</td>
          <td><a download="${esc(entry.receipt.sessionId)}.json" href="data:application/json;base64,${base64(entry.signedJson)}">receipt</a> · <a download="${esc(entry.receipt.sessionId)}.md" href="data:text/markdown;base64,${base64(entry.markdown)}">markdown</a> · <a download="${esc(entry.receipt.sessionId)}.sig" href="data:text/plain;base64,${base64(`${entry.signature}\n`)}">signature</a></td>
        </tr>`).join('')
  const keys = input.publicKeys.map((key, index) => `
        <a download="codetruss-signer-${index + 1}.pem" href="data:application/x-pem-file;base64,${base64(key)}">signer key ${index + 1}</a>`).join(' · ')
  const fingerprintsInline = [...new Set(input.entries
    .map((entry) => entry.receipt.evidence.keyFingerprint)
    .filter((fingerprint): fingerprint is string => Boolean(fingerprint)))]
    .map((fingerprint) => `<span class="mono">${esc(fingerprint)}</span>`)
    .join(', ')
  const excluded = input.excluded.length ? `
      <p><strong>${input.excluded.length} receipt(s) on disk are not in this journal:</strong></p>
      <ul>${input.excluded.map((item) => `<li class="mono">${esc(item.id)} <span class="faint">— ${esc(item.reason)}</span></li>`).join('')}</ul>` : ''
  const journalSignature = input.signature ? `
      <p>The session list and digests above are signed by <span class="mono">${esc(input.signature.fingerprint)}</span> — the signature covers that list, not this page's presentation:</p>
      <pre class="output">${esc(input.signature.manifest)}\n${esc(input.signature.signature)}</pre>` : `
      <p class="faint">The session list carries no signature of its own; each embedded receipt remains individually signed.</p>`
  return `
    <section class="appendix">
      <h2><span class="section-number">A</span>Evidence &amp; verification</h2>
      <p>Everything above is a readable rendering and is not itself signed. The evidence is the signed receipts embedded in this file. To check one:</p>
      <ol>
        <li>Download a receipt, its markdown, and its signature below into one folder.</li>
        <li><strong>Confirm the signing key with its owner through a channel you already trust</strong> — ask them to read you the fingerprint (${fingerprintsInline || '<span class="mono">none recorded</span>'}) and compare it to the key you use. A key downloaded from this document (${keys || '<span class="faint">none embedded</span>'}) can only show the document agrees with itself; it cannot prove who made it.</li>
        <li>Run <span class="mono">codetruss verify-receipt &lt;file&gt;.json --public-key &lt;key&gt;.pem</span> (install: <span class="mono">npm i -g @codetruss/cli</span>). Exit 0 means the receipt and its markdown are intact and were signed by the key you supplied; the patch is committed to by digest inside the receipt rather than carried here. Provenance is only as strong as where you got that key.</li>
      </ol>
      <table class="rows">
        <thead><tr><th>Session</th><th>SHA-256 of signed receipt</th><th>Evidence</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      ${excluded}
      ${journalSignature}
      <p class="faint">What is redacted, precisely: this page's rendering reduces the repository's absolute path to its name${input.includeOutput ? '' : ' and omits verification output'}. The embedded receipts are the producer's exact, unredacted records — that is what makes them verifiable — so they contain the absolute repository path, the full verification commands and output, and the agent command line. Hand this file over knowing it carries them.</p>
    </section>`
}

export function renderJournalHtml(input: JournalInput): string {
  const receipts = input.entries.map((entry) => entry.receipt)
  const first = receipts[0]?.createdAt
  const last = receipts.at(-1)?.createdAt
  const range = first && last
    ? (formatDay(first) === formatDay(last) ? formatDay(first) : `${formatDay(first)} – ${formatDay(last)}`)
    : 'no sessions'
  const fingerprints = [...new Set(receipts.map((receipt) => receipt.evidence.keyFingerprint).filter(Boolean))]
  const entries = input.entries.map((entry, index) => entrySection(entry, index, input.includeOutput)).join('\n')
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Work journal — ${esc(input.repo)}</title>
<style>
:root { --ink: #14181d; --faint: #6b7280; --hair: #e5e7eb; --paper: #ffffff; --ok: #0f766e; --warn: #b45309; --bad: #b91c1c; }
* { box-sizing: border-box; margin: 0; }
body { background: var(--paper); color: var(--ink); font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; padding: 3rem 1.25rem 5rem; }
.page { max-width: 780px; margin: 0 auto; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82em; }
.faint { color: var(--faint); }
.kicker { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.7rem; letter-spacing: 0.14em; text-transform: uppercase; color: var(--faint); border-top: 3px solid var(--ink); display: inline-block; padding-top: 0.6rem; }
h1 { font-size: 2rem; letter-spacing: -0.02em; margin: 0.4rem 0 0.2rem; }
.subtitle { color: var(--faint); margin-bottom: 1.6rem; }
.metrics { display: flex; flex-wrap: wrap; gap: 1.5rem 2.5rem; border-top: 1px solid var(--hair); border-bottom: 1px solid var(--hair); padding: 1rem 0; margin-bottom: 2.5rem; }
.metric-label { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.66rem; letter-spacing: 0.12em; text-transform: uppercase; color: var(--faint); }
.metric-value { font-size: 1.3rem; font-weight: 650; font-variant-numeric: tabular-nums; }
.metric-sub { font-size: 0.8rem; font-weight: 400; color: var(--faint); margin-left: 0.3rem; }
h2 { font-size: 1.25rem; letter-spacing: -0.01em; margin: 2.6rem 0 0.9rem; }
.section-number { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.75rem; color: var(--faint); margin-right: 0.75rem; vertical-align: 0.15em; }
.entry { border-top: 1px solid var(--hair); padding: 1.4rem 0 1.8rem; }
.entry header { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
.entry-meta { font-size: 0.82rem; color: var(--faint); }
.entry-index { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--ink); font-weight: 600; margin-right: 0.4rem; }
.entry h3 { font-size: 1.05rem; margin: 0.5rem 0 0.9rem; line-height: 1.45; }
.verdict { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase; padding: 0.2rem 0.55rem; border-radius: 2px; white-space: nowrap; }
.verdict-pass { color: var(--ok); border: 1px solid currentColor; }
.verdict-review_required { color: var(--warn); border: 1px solid currentColor; }
.verdict-failed { color: var(--bad); border: 1px solid currentColor; }
table.rows { width: 100%; border-collapse: collapse; margin: 0.6rem 0 1rem; font-size: 0.9rem; }
table.rows th { text-align: left; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.66rem; letter-spacing: 0.12em; text-transform: uppercase; color: var(--faint); font-weight: 500; padding: 0.3rem 0.75rem 0.3rem 0; border-bottom: 1px solid var(--hair); }
table.rows td { padding: 0.35rem 0.75rem 0.35rem 0; border-bottom: 1px solid var(--hair); vertical-align: top; overflow-wrap: anywhere; }
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.sha { overflow-wrap: anywhere; }
.add { color: var(--ok); } .del { color: var(--bad); }
.ok { color: var(--ok); font-weight: 600; } .bad { color: var(--bad); font-weight: 600; }
.findings { list-style: none; padding: 0; margin: 0.4rem 0 0.8rem; font-size: 0.9rem; }
.findings li { padding: 0.25rem 0; }
.severity { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.66rem; letter-spacing: 0.08em; text-transform: uppercase; margin-right: 0.4rem; }
.sev-critical, .sev-high { color: var(--bad); } .sev-medium { color: var(--warn); } .sev-low, .sev-info { color: var(--faint); }
.ai-review { font-size: 0.9rem; margin: 0.6rem 0; }
.ai-review .label { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.66rem; letter-spacing: 0.1em; text-transform: uppercase; color: var(--faint); display: block; margin-bottom: 0.15rem; }
.entry-footer { font-size: 0.72rem; color: var(--faint); margin-top: 0.6rem; overflow-wrap: anywhere; }
pre.output { background: #f6f7f8; border: 1px solid var(--hair); padding: 0.7rem; font-size: 0.78rem; overflow-x: auto; margin: 0.4rem 0; white-space: pre-wrap; overflow-wrap: anywhere; }
.appendix { border-top: 3px solid var(--ink); margin-top: 3rem; padding-top: 0.5rem; }
.appendix ol { padding-left: 1.3rem; margin: 0.6rem 0 1rem; }
.appendix li { margin: 0.3rem 0; }
a { color: inherit; }
@media print { body { padding: 0; font-size: 12px; } .entry { break-inside: avoid; } }
</style>
</head>
<body>
<div class="page">
  <span class="kicker">Work journal · CodeTruss receipts</span>
  <h1>${esc(input.repo)}</h1>
  <p class="subtitle">${esc(range)}${fingerprints.length ? ` · prepared from receipts signed by ${fingerprints.map((fp) => `<span class="mono">${esc(fp!)}</span>`).join(', ')}` : ''} · generated ${esc(formatDay(input.generatedAt))}</p>
  ${metricsStrip(input)}
  <h2><span class="section-number">01</span>Sessions</h2>
  ${entries || '<p class="faint">No receipts in the selected range.</p>'}
  ${evidenceAppendix(input)}
</div>
</body>
</html>
`
}
