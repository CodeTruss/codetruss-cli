import { sha256 } from './signing.js'
import type { Verdict } from './types.js'

// The receipt lives in three modules behind this one facade, so every existing
// import site keeps working:
//   receipt-markdown.ts — the rendered bytes, including every frozen per-profile
//                         block. Those bytes sit inside signed receipts, so the
//                         renderers are append-only in practice.
//   receipt-store.ts    — writing, reading, and the privacy-minimized sync copy.
//   receipt-verify.ts   — checking a receipt against its signature.
export { renderLegacyMarkdown, renderMarkdown, renderPriorProfileMarkdown } from './receipt-markdown.js'
export { createSyncEnvelope, receiptIds, resolveReceipt, writeReceipt } from './receipt-store.js'
export {
  acceptedMarkdownRenderings,
  verifyReceipt,
  verifyReceiptIntegrity,
  type ReceiptContentCheck,
  type ReceiptIntegrityResult,
} from './receipt-verify.js'

export function newSessionId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1Z')
  return `${stamp}-${sha256(`${process.pid}:${Math.random()}:${now.getTime()}`).slice(0, 6)}`
}

/**
 * One immutable hook attempt owns one receipt path, even if the hook or CLI
 * process crashes after writing receipt files but before committing its result.
 */
export function hookSessionId(now: Date, attemptId: string): string {
  if (!/^[0-9a-f]{64}$/.test(attemptId)) throw new Error('hook receipt attempt id is invalid')
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.(\d{3})Z$/, '$1Z')
  return `${stamp}-hook-${attemptId}`
}

export function exitCode(verdict: Verdict): number {
  return verdict === 'PASS' ? 0 : verdict === 'REVIEW_REQUIRED' ? 1 : 2
}
