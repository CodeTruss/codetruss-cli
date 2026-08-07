import { createHash } from 'node:crypto'
import { constants as fsConstants, type Stats } from 'node:fs'
import { chmod, lstat, mkdir, mkdtemp, open, readdir, rename, rm } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, win32 } from 'node:path'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { createWriteStream } from 'node:fs'
import { PINNED_GRAMMAR_PACKS, pinnedGrammarPack, type PinnedGrammarPack } from './grammar-pack-manifest.js'

/**
 * Opt-in tree-sitter grammar packs.
 *
 * The CLI ships a hand-written JS-family parser because the WASM grammars are
 * several times its entire release budget. That trade is the right one for the
 * common case, but it is the reason Python has been disclosed as a hosted-only
 * gap. A pack closes that gap for people who want it, WITHOUT putting the bytes
 * in the tarball: they are downloaded once, on an explicit command, into the
 * user's data directory.
 *
 * The security position is deliberate and narrow. This module downloads code
 * that will later be executed in the user's process, so it is not enough to
 * fetch over TLS and hope:
 *
 *  - every artifact is pinned to an exact sha256 compiled into this binary
 *    ({@link PINNED_GRAMMAR_PACKS}), so the origin cannot choose what arrives;
 *  - the digest is checked on download AND re-checked on every load, because a
 *    file verified in March is not a file verified today;
 *  - the bytes that are hashed are the bytes that are RETURNED, and the loader
 *    executes those buffers rather than re-opening the path. Hashing by path and
 *    then executing by path is a time-of-check/time-of-use gap wide enough to
 *    drive a `rename(2)` loop through: an attacker who can write in the pack
 *    directory swaps the artifact between the two reads and gets arbitrary code
 *    execution while every digest check still passes. There is exactly one read
 *    of each artifact per load, from one file descriptor;
 *  - artifacts are opened `O_NOFOLLOW` and every directory this CLI creates is
 *    `lstat`ed, so a symlinked artifact or pack root cannot redirect either the
 *    verification or the install somewhere the digest never covered;
 *  - the only origin is the CodeTruss downloads host — never a third-party CDN,
 *    never a redirect off-origin;
 *  - a download that stalls is abandoned rather than waited out: an origin that
 *    never answers, or answers one byte and holds the socket open, ends in an
 *    error with a reason instead of a hung install;
 *  - any failure — absent, short, over-long, wrong digest, unreadable, stalled —
 *    resolves to "pack unavailable", and the run discloses Python as skipped.
 *    There is no degraded mode in which unverified bytes are executed.
 */

const PRODUCTION_DOWNLOAD_ORIGIN = 'https://codetruss.com'
export const DEV_GRAMMAR_ORIGIN_ENV = 'CODETRUSS_DEV_GRAMMAR_ORIGIN'

/**
 * Where a pack is fetched from.
 *
 * The override exists so tests and local development can serve artifacts from a
 * loopback fixture. It is restricted to loopback for the same reason the sync
 * origin is: an environment variable that could point the downloader at an
 * arbitrary host would hand an attacker with environment access the ability to
 * choose which bytes get executed — and the digest pin is the only thing that
 * would then be standing in the way.
 */
export function resolveGrammarOrigin(explicitDevOrigin = process.env[DEV_GRAMMAR_ORIGIN_ENV]): string {
  if (explicitDevOrigin === undefined || explicitDevOrigin.trim() === '') return PRODUCTION_DOWNLOAD_ORIGIN
  let parsed: URL
  try {
    parsed = new URL(explicitDevOrigin)
  } catch {
    throw new Error(`${DEV_GRAMMAR_ORIGIN_ENV} must be an http(s) loopback origin`)
  }
  const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])
  const hasOnlyOrigin = parsed.pathname === '/' && !parsed.search && !parsed.hash && !parsed.username && !parsed.password
  if (!['http:', 'https:'].includes(parsed.protocol) || !loopbackHosts.has(parsed.hostname) || !hasOnlyOrigin) {
    throw new Error(`${DEV_GRAMMAR_ORIGIN_ENV} must be an http(s) loopback origin without credentials, path, query, or fragment`)
  }
  return parsed.origin
}

/**
 * The user-level data directory, XDG on POSIX and LOCALAPPDATA on Windows.
 *
 * Packs are DATA, not config: they are reproducible downloads a user can delete
 * without losing anything they authored, which is exactly the XDG data/config
 * split. Windows has no XDG, and its nearest equivalent for machine-local,
 * non-roaming data is LOCALAPPDATA — roaming would copy 700 KB of WASM to every
 * machine the profile touches.
 */
export function grammarDataDir(env: NodeJS.ProcessEnv = process.env): string {
  if (process.platform === 'win32') {
    // The win32 flavor explicitly, rather than the platform-default `join`.
    // `C:\Users\…` is not an absolute path to the POSIX variant, so a bare
    // `isAbsolute` here means "correct on Windows, and unverifiable anywhere
    // else" — which is how a Windows-only path bug survives a green CI run.
    const localAppData = env.LOCALAPPDATA?.trim()
    if (localAppData) {
      if (!win32.isAbsolute(localAppData)) throw new Error('LOCALAPPDATA must be an absolute path')
      return win32.join(localAppData, 'codetruss', 'grammars')
    }
    return win32.join(homedir(), 'AppData', 'Local', 'codetruss', 'grammars')
  }
  const configured = env.XDG_DATA_HOME?.trim()
  if (configured && !isAbsolute(configured)) {
    throw new Error('XDG_DATA_HOME must be an absolute user data path')
  }
  return join(configured || join(homedir(), '.local', 'share'), 'codetruss', 'grammars')
}

/** On-disk directory for one pack version, mirroring its published URL path. */
export function grammarPackDir(pack: PinnedGrammarPack, env: NodeJS.ProcessEnv = process.env): string {
  return join(grammarDataDir(env), `${pack.name}-${pack.version}`)
}

/**
 * Read one artifact and hash what was read — never re-open the path.
 *
 * The whole artifact is held in memory on purpose. Streaming the hash and then
 * letting the loader re-read the file is the bug this function exists to make
 * impossible: the returned Buffer is the only thing that is ever executed, so
 * "verified" and "executed" are the same bytes by construction rather than by
 * the hope that nothing rewrote the file in between. 738 KB is a cheap price.
 *
 * `O_NOFOLLOW` refuses a symlinked artifact atomically, and `O_NONBLOCK` keeps a
 * FIFO left in the artifact's place from parking the process on `open`. The size
 * and type come from `fstat` on the open descriptor rather than from a second
 * `stat` of the name, so they describe the file that was actually read.
 */
async function readVerifiedArtifact(
  path: string,
  expected: { name: string; bytes: number; sha256: string },
): Promise<{ bytes: Buffer } | { reason: string }> {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0)
  let handle
  try {
    handle = await open(path, flags)
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return { reason: `${expected.name} is missing from the installed pack` }
    if (code === 'ELOOP') return { reason: `${expected.name} is a symbolic link, not a regular file` }
    return { reason: `${expected.name} is unreadable: ${(error as Error).message}` }
  }
  try {
    const info = await handle.stat()
    if (!info.isFile()) return { reason: `${expected.name} is not a regular file` }
    // Size first: it bounds the read, so a padded artifact is rejected before
    // this process commits to holding it.
    if (info.size !== expected.bytes) {
      return { reason: `${expected.name} is ${info.size} bytes, expected ${expected.bytes}` }
    }
    let bytes: Buffer
    try {
      bytes = await handle.readFile()
    } catch (error) {
      return { reason: `${expected.name} could not be read: ${(error as Error).message}` }
    }
    // A file that grew between fstat and read would hash differently anyway, but
    // saying so by length is a clearer reason than a digest mismatch.
    if (bytes.length !== expected.bytes) {
      return { reason: `${expected.name} is ${bytes.length} bytes, expected ${expected.bytes}` }
    }
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (digest !== expected.sha256) {
      return { reason: `${expected.name} has digest ${digest}, expected ${expected.sha256}` }
    }
    return { bytes }
  } finally {
    await handle.close().catch(() => {})
  }
}

/**
 * Whether a directory this CLI created is still one it can trust.
 *
 * `mkdir`'s `mode` only applies to directories it actually creates, so a root
 * pre-created loose stays loose — and POSIX write permission on the PARENT of a
 * pack is enough to `rename` the pack away and substitute one, no permission on
 * the files required. A symlinked root is worse still: it redirects the install
 * and every later read somewhere the pinned digests were never computed over.
 *
 * The ownership and mode checks are POSIX-only; Windows ACLs are not expressible
 * in `st_mode` and pretending otherwise would reject every Windows install.
 */
function directoryTrustProblem(info: Stats, path: string): string | undefined {
  if (info.isSymbolicLink()) return `${path} is a symbolic link, not a real directory`
  if (!info.isDirectory()) return `${path} is not a directory`
  if (typeof process.getuid !== 'function') return undefined
  if (info.uid !== process.getuid()) return `${path} is owned by uid ${info.uid}, not by this user`
  // WRITABLE, not merely readable. A world-readable root leaks nothing that is
  // not already published, and failing a load over it would be a dead end for no
  // security gain; a writable one is what lets a pack be renamed away and
  // replaced without any permission on the files themselves.
  if ((info.mode & 0o022) !== 0) {
    return `${path} is writable by group or other (mode ${(info.mode & 0o777).toString(8)})`
  }
  return undefined
}

/**
 * The directories this CLI creates and therefore gets to have opinions about.
 *
 * Deliberately not the whole path: the user's data home is theirs, and on macOS
 * `os.tmpdir()` is already a symlink, so demanding a link-free ancestry would
 * reject ordinary systems while proving nothing. What matters is that the two
 * components CodeTruss makes — and the pack directory inside them — are real,
 * ours, and not writable by anyone else.
 */
function codetrussOwnedRoots(env: NodeJS.ProcessEnv): string[] {
  const root = grammarDataDir(env)
  return [dirname(root), root]
}

export type GrammarPackState =
  /** No pack directory on disk. The user has never installed it, or removed it. */
  | { status: 'absent'; pack: PinnedGrammarPack }
  /**
   * Present and every artifact matches its pinned digest.
   *
   * `contents` holds the exact buffers that were hashed, keyed by artifact name.
   * The loader executes these and never re-opens the paths — that identity is
   * what makes "nothing unverified was executed" a fact rather than a wish.
   */
  | { status: 'verified'; pack: PinnedGrammarPack; dir: string; contents: ReadonlyMap<string, Buffer> }
  /** Present but not trustworthy. Never loaded; the reason is disclosed verbatim. */
  | { status: 'failed'; pack: PinnedGrammarPack; dir: string; reason: string }

/**
 * Check an installed pack against the digests compiled into this binary.
 *
 * Called before every load, not only at install time. A pack sits in a
 * user-writable directory for months; re-verifying is the difference between
 * "these bytes were trustworthy when downloaded" and "these bytes are
 * trustworthy now".
 */
export async function inspectGrammarPack(
  name: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<GrammarPackState> {
  const pack = pinnedGrammarPack(name)
  if (!pack) throw new Error(`unknown grammar pack ${name}; expected ${PINNED_GRAMMAR_PACKS.map((entry) => entry.name).join(', ')}`)
  const dir = grammarPackDir(pack, env)

  // Absence is decided by the pack directory alone, so a user who never
  // installed anything is told "not installed" rather than handed a complaint
  // about a directory they have no reason to care about.
  try {
    await lstat(dir)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'absent', pack }
    return { status: 'failed', pack, dir, reason: `pack directory is unreadable: ${(error as Error).message}` }
  }

  for (const path of [...codetrussOwnedRoots(env), dir]) {
    let info: Stats
    try {
      info = await lstat(path)
    } catch (error) {
      return { status: 'failed', pack, dir, reason: `${path} is unreadable: ${(error as Error).message}` }
    }
    const problem = directoryTrustProblem(info, path)
    if (problem) return { status: 'failed', pack, dir, reason: problem }
  }

  const contents = new Map<string, Buffer>()
  for (const file of pack.files) {
    const read = await readVerifiedArtifact(join(dir, file.name), file)
    if ('reason' in read) return { status: 'failed', pack, dir, reason: read.reason }
    contents.set(file.name, read.bytes)
  }

  // An extra file in the pack directory is not loaded, but it does mean the
  // directory is not what this CLI published, and saying so is cheaper than
  // explaining later why a tampered install looked healthy.
  let present: string[]
  try {
    present = (await readdir(dir)).sort()
  } catch (error) {
    return { status: 'failed', pack, dir, reason: `pack directory is unreadable: ${(error as Error).message}` }
  }
  const expected = pack.files.map((file) => file.name).sort()
  if (present.join('\n') !== expected.join('\n')) {
    return { status: 'failed', pack, dir, reason: `pack directory holds unexpected files: ${present.join(', ')}` }
  }

  return { status: 'verified', pack, dir, contents }
}

/**
 * How long one artifact download may take, and how long it may say nothing.
 *
 * Two clocks, because they catch different failures. The total budget bounds a
 * transfer that is progressing but will not finish; the idle budget catches the
 * drip feed — a server that writes one byte and then holds the socket open
 * forever, which no total-only budget shorter than "forever" ever ends, and
 * which `fetch` on its own will wait out indefinitely. `grammars install` is a
 * foreground command a person is watching, so an origin that stalls has to fail
 * with a sentence, not hang.
 *
 * The values are generous on purpose: 738 KB over a bad hotel connection is
 * still well inside them, and a false abort would look exactly like a tampered
 * download to a user who cannot tell the two apart.
 */
export interface GrammarDownloadLimits {
  /** Whole-transfer budget for one artifact, from request to last byte. */
  totalMs: number
  /** Longest silence allowed — between the request and the first byte, or between two chunks. */
  idleMs: number
}

const DEFAULT_DOWNLOAD_LIMITS: GrammarDownloadLimits = { totalMs: 120_000, idleMs: 20_000 }

/**
 * Download one artifact into `target`, verifying as the bytes arrive.
 *
 * The pinned length is enforced DURING the stream rather than after it, so a
 * hostile or broken origin cannot fill the user's disk before the digest gets a
 * chance to disagree.
 *
 * Both deadlines drive one `AbortController` rather than `AbortSignal.timeout`
 * so the reason the transfer was abandoned survives into the error: an aborted
 * `fetch` reports only "This operation was aborted", which tells a user nothing
 * about whether their network stalled or the origin is misbehaving.
 */
async function downloadVerified(
  url: string,
  target: string,
  expected: { bytes: number; sha256: string },
  limits: GrammarDownloadLimits,
): Promise<void> {
  const controller = new AbortController()
  /** Set only when a deadline fired, so an abort is reported as itself. */
  let abandoned: string | undefined
  const abandon = (reason: string) => {
    if (abandoned) return
    abandoned = reason
    controller.abort()
  }
  const total = setTimeout(() => abandon(`${url} did not finish within ${limits.totalMs}ms`), limits.totalMs)
  let idle: ReturnType<typeof setTimeout> | undefined
  const restartIdle = () => {
    clearTimeout(idle)
    idle = setTimeout(() => abandon(`${url} sent no data for ${limits.idleMs}ms`), limits.idleMs)
  }

  try {
    // Started before the request, so a server that accepts the connection and
    // never answers is on the same clock as one that stalls mid-body.
    restartIdle()
    const response = await fetch(url, {
      redirect: 'error',
      headers: { accept: 'application/octet-stream' },
      signal: controller.signal,
    })
    if (!response.ok) throw new Error(`${url} responded ${response.status}`)
    if (!response.body) throw new Error(`${url} returned no body`)

    const hash = createHash('sha256')
    let received = 0
    const measured = new Readable({ read() {} })
    const source = Readable.fromWeb(response.body as Parameters<typeof Readable.fromWeb>[0])
    source.on('data', (chunk: Buffer) => {
      restartIdle()
      received += chunk.length
      if (received > expected.bytes) {
        measured.destroy(new Error(`${url} sent more than the pinned ${expected.bytes} bytes`))
        source.destroy()
        return
      }
      hash.update(chunk)
      measured.push(chunk)
    })
    source.on('end', () => measured.push(null))
    source.on('error', (error: Error) => measured.destroy(error))

    await pipeline(measured, createWriteStream(target, { mode: 0o600 }))

    if (received !== expected.bytes) throw new Error(`${url} sent ${received} bytes, expected ${expected.bytes}`)
    const digest = hash.digest('hex')
    if (digest !== expected.sha256) throw new Error(`${url} has digest ${digest}, expected ${expected.sha256}`)
  } catch (error) {
    throw abandoned ? new Error(abandoned) : error
  } finally {
    clearTimeout(total)
    clearTimeout(idle)
  }
}

/**
 * Make one of this CLI's own directories safe to install through, or refuse.
 *
 * Install is the one moment the CLI may FIX what it finds rather than only
 * report it, so a root that is not already the 0700 `mkdir` asked for is
 * tightened to it — a dead end is a bad answer to a condition one `chmod`
 * resolves, and a root left 0755 by an earlier version is the common case. A
 * symlink or a directory owned by someone else is refused outright: both mean
 * the install would land somewhere this process does not control, and no mode
 * bit makes that acceptable.
 */
async function secureExistingRoot(path: string): Promise<void> {
  const info = await lstat(path)
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`${path} is not a real directory; refusing to install through it`)
  }
  if (typeof process.getuid !== 'function') return
  if (info.uid !== process.getuid()) {
    throw new Error(`${path} is owned by uid ${info.uid}, not by this user; refusing to install into it`)
  }
  if ((info.mode & 0o077) !== 0) await chmod(path, 0o700)
}

export interface GrammarInstallResult {
  pack: PinnedGrammarPack
  dir: string
  /** True when a verified copy was already present and nothing was downloaded. */
  alreadyInstalled: boolean
  bytes: number
}

/**
 * Install a pack: download every artifact to a scratch directory, verify each,
 * and only then move the whole thing into place.
 *
 * Staging matters. A per-file install that fails halfway leaves a directory that
 * is neither absent nor verified, and the next run has to reason about a partial
 * state. Assembling in scratch means the pack directory only ever appears
 * complete and verified.
 */
export async function installGrammarPack(
  name: string,
  env: NodeJS.ProcessEnv = process.env,
  limits: GrammarDownloadLimits = DEFAULT_DOWNLOAD_LIMITS,
): Promise<GrammarInstallResult> {
  const existing = await inspectGrammarPack(name, env)
  const pack = existing.pack
  const bytes = pack.files.reduce((sum, file) => sum + file.bytes, 0)
  if (existing.status === 'verified') {
    return { pack, dir: existing.dir, alreadyInstalled: true, bytes }
  }

  const origin = resolveGrammarOrigin(env[DEV_GRAMMAR_ORIGIN_ENV])
  const root = grammarDataDir(env)
  await mkdir(root, { recursive: true, mode: 0o700 })
  // `mkdir` said nothing about a directory that already existed, and this is the
  // one moment the CLI is allowed to fix that rather than only report it.
  for (const path of codetrussOwnedRoots(env)) await secureExistingRoot(path)
  const scratch = await mkdtemp(join(root, `.${pack.name}-${pack.version}.`))
  try {
    for (const file of pack.files) {
      await downloadVerified(`${origin}${file.url}`, join(scratch, file.name), file, limits)
    }
    const target = grammarPackDir(pack, env)
    // A failed or partial previous install is replaced wholesale rather than
    // patched, so the result is exactly what this CLI expects or nothing.
    await rm(target, { recursive: true, force: true })
    await rename(scratch, target)
    const verified = await inspectGrammarPack(name, env)
    if (verified.status !== 'verified') {
      const reason = verified.status === 'failed' ? verified.reason : 'the installed pack disappeared'
      throw new Error(`installed pack failed verification: ${reason}`)
    }
    return { pack, dir: verified.dir, alreadyInstalled: false, bytes }
  } catch (error) {
    await rm(scratch, { recursive: true, force: true }).catch(() => {})
    throw error
  }
}

/** Remove an installed pack. Absent is success — the requested end state holds. */
export async function uninstallGrammarPack(
  name: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ pack: PinnedGrammarPack; removed: boolean }> {
  const pack = pinnedGrammarPack(name)
  if (!pack) throw new Error(`unknown grammar pack ${name}`)
  const dir = grammarPackDir(pack, env)
  // `lstat`, so a symlink standing in for the pack directory counts as present
  // and gets removed, rather than reporting "not installed" and leaving the
  // redirect in place for the next install to write through.
  try {
    await lstat(dir)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { pack, removed: false }
    throw error
  }
  await rm(dir, { recursive: true, force: true })
  return { pack, removed: true }
}
