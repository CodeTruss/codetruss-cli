import { existsSync } from 'node:fs'
import { chmod, mkdir, readFile, realpath, rename, unlink, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { sha256 } from './signing.js'

const TRUST_VERSION = 1 as const
const TRUST_FILE_NAME = 'verify-command-trust.json'

/**
 * Where the user-local trust store lives. Aligned with cliAuthFilePath(): both
 * are user config under the same root, and honouring XDG_CONFIG_HOME in one but
 * not the other silently split a single user's CodeTruss state across two
 * directories.
 *
 * Migration: an existing store at the legacy `~/.config` path keeps being used
 * even once XDG_CONFIG_HOME is set, so setting that variable never orphans
 * approvals someone already made.
 */
export function verifyTrustFilePath(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.XDG_CONFIG_HOME?.trim()
  if (configured && !isAbsolute(configured)) {
    throw new Error('XDG_CONFIG_HOME must be an absolute user config path')
  }
  const legacy = join(homedir(), '.config', 'codetruss', TRUST_FILE_NAME)
  if (!configured) return legacy
  const preferred = join(configured, 'codetruss', TRUST_FILE_NAME)
  if (existsSync(preferred) || !existsSync(legacy)) return preferred
  return legacy
}

interface VerifyTrustStore {
  version: typeof TRUST_VERSION
  trusted: Record<string, { trustedAt: string }>
}

export interface VerifyCommandTrustStatus {
  hash: string
  trusted: boolean
  trustFile: string
}

async function canonicalRoot(root: string): Promise<string> {
  try {
    return await realpath(root)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return resolve(root)
    throw error
  }
}

/**
 * Bind approval to the canonical repository location and the exact, ordered
 * command strings. Any repository-config command change produces a new hash.
 */
export async function verifyCommandTrustHash(root: string, commands: string[]): Promise<string> {
  return sha256(JSON.stringify({
    version: TRUST_VERSION,
    repoRoot: await canonicalRoot(root),
    commands,
  }))
}

function emptyStore(): VerifyTrustStore {
  return { version: TRUST_VERSION, trusted: {} }
}

async function readStore(path: string): Promise<VerifyTrustStore> {
  let parsed: unknown
  try {
    parsed = JSON.parse(await readFile(path, 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return emptyStore()
    throw new Error(`could not read verify-command trust store: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('verify-command trust store is invalid; refusing to trust repository commands')
  }
  const value = parsed as Record<string, unknown>
  if (value.version !== TRUST_VERSION || !value.trusted || typeof value.trusted !== 'object' || Array.isArray(value.trusted)) {
    throw new Error('verify-command trust store is invalid; refusing to trust repository commands')
  }
  const trusted = value.trusted as Record<string, unknown>
  for (const [hash, entry] of Object.entries(trusted)) {
    if (!/^[0-9a-f]{64}$/.test(hash) || !entry || typeof entry !== 'object' || Array.isArray(entry)
      || typeof (entry as Record<string, unknown>).trustedAt !== 'string') {
      throw new Error('verify-command trust store is invalid; refusing to trust repository commands')
    }
  }
  return parsed as VerifyTrustStore
}

async function writeStore(path: string, store: VerifyTrustStore): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  try {
    await writeFile(temporary, `${JSON.stringify(store, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' })
    await rename(temporary, path)
    await chmod(path, 0o600)
  } catch (error) {
    // A failed atomic replace must not turn a partial file into trusted state.
    try { await unlink(temporary) } catch {}
    throw error
  }
}

export async function verifyCommandTrustStatus(
  root: string,
  commands: string[],
  trustFile = verifyTrustFilePath(),
): Promise<VerifyCommandTrustStatus> {
  const hash = await verifyCommandTrustHash(root, commands)
  const store = await readStore(trustFile)
  return { hash, trusted: Object.hasOwn(store.trusted, hash), trustFile }
}

/** Persist an explicit user approval without storing repository paths or commands. */
export async function trustVerifyCommands(
  root: string,
  commands: string[],
  trustFile = verifyTrustFilePath(),
  now = new Date(),
): Promise<VerifyCommandTrustStatus> {
  const hash = await verifyCommandTrustHash(root, commands)
  const store = await readStore(trustFile)
  store.trusted[hash] = { trustedAt: now.toISOString() }
  await writeStore(trustFile, store)
  return { hash, trusted: true, trustFile }
}

export async function revokeVerifyCommands(
  root: string,
  commands: string[],
  trustFile = verifyTrustFilePath(),
): Promise<VerifyCommandTrustStatus> {
  const hash = await verifyCommandTrustHash(root, commands)
  const store = await readStore(trustFile)
  delete store.trusted[hash]
  await writeStore(trustFile, store)
  return { hash, trusted: false, trustFile }
}
