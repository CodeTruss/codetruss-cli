import { readFile, readdir, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { verifyReceiptIntegrity, type ReceiptContentCheck } from './receipt.js'
import { normalizePublicKey, publicKeyFingerprint } from './signing.js'

/**
 * `codetruss verify-receipt` — the supported way to check a receipt you did not
 * produce.
 *
 * The product's claim is that a receipt can be re-checked later. Until this
 * command existed that was only true for the machine that signed it: `codetruss
 * verify` measures a receipt against the keys THIS repository pins, which is
 * right for your own history and useless to the client, auditor or acquirer the
 * receipt was written for. They were left to write their own verifier.
 *
 * It has to say two different things without ever letting them blur:
 *
 *   INTEGRITY — these bytes have not changed since they were signed. Anyone can
 *   check it, using the key inside the receipt and the digests it records.
 *
 *   PROVENANCE — a named party signed them. Checkable ONLY against a key that
 *   arrived some other way. A receipt vouching for its own key establishes
 *   nothing about who wrote it: forging one takes a keypair and a minute.
 *
 * So a bare run can never print the word "verified" on its own, and a green
 * exit is reachable only once the reader has supplied a key from outside the
 * file. Reporting integrity as though it settled authorship would be precisely
 * the failure this product exists to prevent.
 */

/** Both claims hold. */
const EXIT_VERIFIED = 0
/** The bytes are intact, but nothing here says who signed them. */
const EXIT_INTACT_UNATTRIBUTED = 1
/** These bytes are not what was signed. */
const EXIT_NOT_INTACT = 2

interface SuppliedKey {
  source: string
  fingerprint: string
}

async function readSuppliedKeys(paths: string[]): Promise<SuppliedKey[]> {
  const keys: SuppliedKey[] = []
  for (const path of paths) {
    let pem: string
    try {
      pem = await readFile(path, 'utf8')
    } catch (error) {
      throw new Error(`could not read the public key at ${path}: ${error instanceof Error ? error.message : String(error)}`)
    }
    try {
      keys.push({ source: path, fingerprint: publicKeyFingerprint(normalizePublicKey(pem)) })
    } catch {
      throw new Error(`${path} is not a PEM public key`)
    }
  }
  return keys
}

/** Accept the receipt itself, or the directory a published bundle arrives as. */
async function resolveReceiptPath(path: string): Promise<string> {
  const isDirectory = await stat(path).then((entry) => entry.isDirectory(), (error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') throw new Error(`no such path: ${path}`)
    throw error
  })
  if (!isDirectory) return path
  const found = (await readdir(path)).filter((name) => name.endsWith('.json')).sort()
  if (found.length === 0) throw new Error(`${path} contains no receipt .json file`)
  if (found.length > 1) throw new Error(`${path} contains ${found.length} .json files; name the one to check (${found.join(', ')})`)
  return join(path, found[0])
}

function checkLine(check: ReceiptContentCheck): string {
  const marker = check.status === 'ok' ? 'ok  ' : check.status === 'failed' ? 'FAIL' : 'skip'
  return `  ${marker}  ${check.label}${check.detail ? `\n        ${check.detail}` : ''}\n`
}

export async function runVerifyReceiptCommand(
  path: string,
  publicKeyPaths: string[] = [],
  write: (text: string) => void = (text) => process.stdout.write(text),
): Promise<number> {
  const suppliedKeys = await readSuppliedKeys(publicKeyPaths)
  const jsonPath = await resolveReceiptPath(path)
  const result = await verifyReceiptIntegrity(jsonPath)

  write(`receipt ${result.receipt.sessionId} — verdict ${result.receipt.verdict}\n`)
  write(`signing key ${result.signerFingerprint ?? '(unreadable)'} — carried by the receipt, which is not evidence of who made it\n\n`)

  // "Established" must never quietly mean "established over the parts that
  // happened to be here". A withheld file is a hole in the evidence and the
  // headline is where a reader will look for it.
  const skipped = result.checks.filter((check) => check.status === 'skipped').length
  const unchecked = result.intact && skipped > 0
    ? ` — over what was published; ${skipped} recorded piece${skipped === 1 ? '' : 's'} of evidence ${skipped === 1 ? 'is' : 'are'} absent and unchecked`
    : ''
  write(`integrity: ${result.intact ? 'ESTABLISHED' : 'NOT ESTABLISHED'}${unchecked}\n`)
  for (const check of result.checks) write(checkLine(check))
  write('\n')

  if (!result.intact) {
    // Whose key signed altered bytes is not a question worth answering: the
    // signature did not hold, so nothing here attributes anything to anyone.
    write('provenance: NOT CHECKED\n')
    write('  Provenance means nothing over bytes that are not what was signed.\n\n')
    write('These bytes are not the bytes that were signed. Do not rely on this receipt.\n')
    return EXIT_NOT_INTACT
  }

  const matched = suppliedKeys.find((key) => key.fingerprint === result.signerFingerprint)
  if (matched) {
    write('provenance: ESTABLISHED\n')
    write(`  The receipt is signed by the key you supplied (${matched.source}).\n\n`)
    write(
      'Both claims hold: these bytes are unchanged since signing, and they were signed by that key.\n'
      + 'Neither proves the analysis described here actually ran, or that its conclusions are correct.\n',
    )
    return EXIT_VERIFIED
  }

  write('provenance: NOT ESTABLISHED\n')
  write(suppliedKeys.length === 0
    ? '  No --public-key was supplied, so the only key available is the one this receipt carries.\n'
      + '  Anyone can generate a key and sign a receipt of their own with it.\n'
    : `  This receipt is signed by ${result.signerFingerprint}, which is not ${suppliedKeys.length === 1 ? 'the key' : 'among the keys'} you supplied `
      + `(${suppliedKeys.map((key) => `${key.fingerprint} from ${key.source}`).join(', ')}).\n`)
  write('\n')
  write(
    'Integrity alone proves these bytes have not changed since someone signed them.\n'
    + 'It does not prove who that someone is, that the analysis ran, or that its conclusions are correct.\n'
    + `${suppliedKeys.length === 0 ? 'Get the signer\'s public key from them directly — not from this file — and re-run with --public-key <file>.\n' : 'Until that key is one you obtained from the party you mean to trust, this receipt is unattributed.\n'}`,
  )
  return EXIT_INTACT_UNATTRIBUTED
}
