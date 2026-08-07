import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto'
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export interface SigningKey {
  privateKey: KeyObject
  publicKey: string
  fingerprint: string
}

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

export function signingKeyPath(): string {
  return process.env.CODETRUSS_SIGNING_KEY ?? join(homedir(), '.config', 'codetruss', 'signing-private.pem')
}

export function normalizePublicKey(publicKey: string): string {
  return createPublicKey(publicKey).export({ type: 'spki', format: 'pem' }).toString()
}

export function publicKeyFingerprint(publicKey: string): string {
  const der = createPublicKey(publicKey).export({ type: 'spki', format: 'der' })
  return sha256(der).slice(0, 16)
}

export async function loadSigningKey(create = false): Promise<SigningKey> {
  const path = signingKeyPath()
  let pem: Buffer
  try {
    pem = await readFile(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    if (!create) {
      throw new Error(`trusted signing key not found at ${path}; run codetruss init or set CODETRUSS_SIGNING_KEY`)
    }
    const pair = generateKeyPairSync('ed25519')
    pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) as Buffer
    await mkdir(dirname(path), { recursive: true })
    await writeFile(path, pem, { mode: 0o600 })
    await chmod(path, 0o600)
  }
  const privateKey = createPrivateKey(pem)
  const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString()
  return { privateKey, publicKey, fingerprint: publicKeyFingerprint(publicKey) }
}

/**
 * The repository pin is a SET of trusted signers, so each developer signs with
 * their own key and keeps per-signer attribution. The failure message must
 * never suggest obtaining someone else's private key — that would destroy the
 * attribution the receipt exists to provide.
 */
export async function requireTrustedSigningKey(pinnedPublicKey?: string | string[]): Promise<SigningKey> {
  const key = await loadSigningKey(true)
  const pins = (Array.isArray(pinnedPublicKey) ? pinnedPublicKey : [pinnedPublicKey]).filter(
    (pin): pin is string => typeof pin === 'string' && pin.trim().length > 0,
  )
  if (pins.length > 0) {
    const fingerprints = pins.map((pin) => publicKeyFingerprint(pin))
    if (!fingerprints.includes(key.fingerprint)) {
      throw new Error(
        `this repository trusts ${fingerprints.join(', ')} but your local signing key is ${key.fingerprint}; `
        + 'add yours with codetruss verify-policy trust-key (or have a maintainer append it to signing.publicKeys)',
      )
    }
  }
  return key
}

export function signBytes(bytes: Buffer | string, privateKey: KeyObject): string {
  return sign(null, Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes), privateKey).toString('base64')
}

export function verifyBytes(bytes: Buffer | string, publicKey: string, signature: string): boolean {
  return verify(
    null,
    Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes),
    createPublicKey(publicKey),
    Buffer.from(signature, 'base64'),
  )
}
