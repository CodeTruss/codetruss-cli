import { createHash } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { chmod, lstat, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { PINNED_GRAMMAR_PACKS, pinnedGrammarPack } from '../src/grammar-pack-manifest.js'
import {
  DEV_GRAMMAR_ORIGIN_ENV,
  grammarDataDir,
  grammarPackDir,
  inspectGrammarPack,
  installGrammarPack,
  resolveGrammarOrigin,
  uninstallGrammarPack,
} from '../src/grammar-pack.js'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const publishedDir = join(repoRoot, 'public', 'downloads', 'grammars')

const cleanup: string[] = []
afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

/**
 * Serve the real published artifacts over loopback.
 *
 * The install path is only worth testing against the actual bytes: a fixture
 * with invented content would verify against an invented pin and prove nothing
 * about whether the CLI can install what this repository publishes.
 */
let server: Server
let origin: string
/** Bytes to answer with instead of the published file, for tamper cases. */
let override: Buffer | null = null

beforeAll(async () => {
  server = createServer((req, res) => {
    const path = decodeURIComponent((req.url ?? '').split('?')[0])
    const prefix = '/downloads/grammars/'
    if (!path.startsWith(prefix) || path.includes('..')) {
      res.writeHead(404).end()
      return
    }
    if (override) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' }).end(override)
      return
    }
    readFile(join(publishedDir, path.slice(prefix.length))).then(
      (bytes) => res.writeHead(200, { 'content-type': 'application/octet-stream' }).end(bytes),
      () => res.writeHead(404).end(),
    )
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  origin = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`
})

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
})

async function scratchEnv(): Promise<NodeJS.ProcessEnv> {
  const home = await mkdtemp(join(tmpdir(), 'codetruss-grammars-'))
  cleanup.push(home)
  return { XDG_DATA_HOME: home, [DEV_GRAMMAR_ORIGIN_ENV]: origin }
}

describe('grammar pack storage location', () => {
  it('puts packs under XDG_DATA_HOME, not the config directory', () => {
    const dir = grammarDataDir({ XDG_DATA_HOME: '/data' })
    // Packs are reproducible downloads, not authored settings.
    expect(dir).toBe(join('/data', 'codetruss', 'grammars'))
  })

  it('refuses a relative XDG_DATA_HOME rather than resolving it against the cwd', () => {
    expect(() => grammarDataDir({ XDG_DATA_HOME: 'relative/path' })).toThrow(/absolute/)
  })

  it('resolves the Windows data directory from LOCALAPPDATA', () => {
    const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    try {
      // LOCALAPPDATA, not APPDATA: 700 KB of WASM must not roam between machines.
      expect(grammarDataDir({ LOCALAPPDATA: 'C:\\Users\\x\\AppData\\Local' }))
        .toBe('C:\\Users\\x\\AppData\\Local\\codetruss\\grammars')
      expect(() => grammarDataDir({ LOCALAPPDATA: 'Local' })).toThrow(/absolute/)
    } finally {
      Object.defineProperty(process, 'platform', platform)
    }
  })
})

describe('the download origin is not a free parameter', () => {
  it('defaults to the CodeTruss downloads host', () => {
    expect(resolveGrammarOrigin(undefined)).toBe('https://codetruss.com')
    expect(resolveGrammarOrigin('')).toBe('https://codetruss.com')
  })

  it('accepts a loopback override for development and rejects anything else', () => {
    expect(resolveGrammarOrigin('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080')
    // Environment access must not become "choose which code gets executed".
    expect(() => resolveGrammarOrigin('https://evil.example.com')).toThrow(/loopback/)
    expect(() => resolveGrammarOrigin('http://localhost/path')).toThrow(/loopback/)
    expect(() => resolveGrammarOrigin('not a url')).toThrow(/loopback/)
  })
})

describe('installing a pack', () => {
  it('downloads every pinned artifact and verifies each digest', async () => {
    const env = await scratchEnv()
    const result = await installGrammarPack('python', env)

    expect(result.alreadyInstalled).toBe(false)
    const pack = pinnedGrammarPack('python')!
    for (const file of pack.files) {
      const info = await stat(join(result.dir, file.name))
      expect(info.size).toBe(file.bytes)
    }
    await expect(inspectGrammarPack('python', env)).resolves.toMatchObject({ status: 'verified' })
  })

  it('is idempotent: a verified pack is not re-downloaded', async () => {
    const env = await scratchEnv()
    await installGrammarPack('python', env)
    const second = await installGrammarPack('python', env)
    expect(second.alreadyInstalled).toBe(true)
  })

  it('refuses bytes that do not match the pin, and leaves nothing behind', async () => {
    const env = await scratchEnv()
    override = Buffer.from('not a grammar')
    try {
      await expect(installGrammarPack('python', env)).rejects.toThrow(/bytes|digest/)
    } finally {
      override = null
    }
    // A rejected download must not leave a half-installed pack that a later run
    // could mistake for a real one.
    await expect(inspectGrammarPack('python', env)).resolves.toMatchObject({ status: 'absent' })
  })

  it('rejects an unknown pack name instead of inventing a download URL', async () => {
    const env = await scratchEnv()
    await expect(installGrammarPack('haskell', env)).rejects.toThrow(/unknown grammar pack/)
  })
})

describe('a pack is re-verified on every load, not only at install', () => {
  it('reports a flipped byte as failed, naming the artifact', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    const target = join(dir, 'tree-sitter-python.wasm')
    const bytes = await readFile(target)
    bytes[100] ^= 0xff
    await writeFile(target, bytes)

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toContain('tree-sitter-python.wasm')
    expect(state.reason).toContain('digest')
  })

  it('reports a truncated artifact by size before hashing it', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    await writeFile(join(dir, 'tree-sitter.wasm'), Buffer.alloc(10))

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toMatch(/is 10 bytes, expected/)
  })

  it('reports a missing artifact rather than loading a partial pack', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    await rm(join(dir, 'tree-sitter.js'))

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toContain('tree-sitter.js is missing')
  })

  it('reports an unexpected file in the pack directory', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    await writeFile(join(dir, 'extra.js'), 'console.log(1)')

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toContain('extra.js')
  })

  /**
   * The load-bearing property of the whole design: the bytes that were hashed
   * are the bytes the caller gets. A loader handed a path instead has verified
   * one file and will execute whatever is at that name a moment later, and the
   * gap is long enough — two more digests and a `readdir` — for a `rename(2)`
   * loop to land a hostile module in it.
   */
  it('returns the exact buffers it hashed, not a path to re-read', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    const state = await inspectGrammarPack('python', env)
    if (state.status !== 'verified') throw new Error('expected a verified pack')

    const pack = pinnedGrammarPack('python')!
    for (const file of pack.files) {
      const held = state.contents.get(file.name)
      expect(held).toBeInstanceOf(Buffer)
      expect(createHash('sha256').update(held!).digest('hex')).toBe(file.sha256)
      expect(held!.equals(await readFile(join(dir, file.name)))).toBe(true)
    }

    // Rewriting every artifact after the fact cannot reach the buffers already
    // returned — which is precisely why the loader is safe to execute them.
    for (const file of pack.files) await writeFile(join(dir, file.name), Buffer.alloc(file.bytes, 0x41))
    for (const file of pack.files) {
      expect(createHash('sha256').update(state.contents.get(file.name)!).digest('hex')).toBe(file.sha256)
    }
  })

  it('replaces a failed pack wholesale on reinstall', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    await writeFile(join(dir, 'extra.js'), 'console.log(1)')
    expect((await inspectGrammarPack('python', env)).status).toBe('failed')

    const reinstalled = await installGrammarPack('python', env)
    expect(reinstalled.alreadyInstalled).toBe(false)
    await expect(inspectGrammarPack('python', env)).resolves.toMatchObject({ status: 'verified' })
  })
})

/**
 * `stat` follows symlinks and `mkdir`'s mode only applies to directories it
 * creates, so the naive version of this module accepts a symlinked artifact as
 * verified, installs straight through a symlinked pack root, and leaves a
 * pre-existing loose root loose. Each one turns "needs write inside a 0700
 * directory" into something much cheaper — and on a shared host, into a
 * cross-user problem.
 *
 * POSIX-only: `symlink` needs a privilege on Windows, and `st_mode` says nothing
 * useful about an ACL there.
 */
describe.skipIf(process.platform === 'win32')('symlinks and loose permissions', () => {
  it('rejects a symlinked artifact instead of hashing what it points at', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    // The link target holds the genuine, pinned bytes: following it would
    // verify perfectly, which is exactly the trap.
    const elsewhere = await mkdtemp(join(tmpdir(), 'codetruss-link-target-'))
    cleanup.push(elsewhere)
    const target = join(elsewhere, 'tree-sitter.js')
    await rename(join(dir, 'tree-sitter.js'), target)
    await symlink(target, join(dir, 'tree-sitter.js'))

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toContain('tree-sitter.js')
    expect(state.reason).toContain('symbolic link')
  })

  it('rejects a symlinked pack root even when the pack behind it verifies', async () => {
    const env = await scratchEnv()
    await installGrammarPack('python', env)
    const root = grammarDataDir(env)
    await rename(root, `${root}-real`)
    await symlink(`${root}-real`, root)

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toContain('symbolic link')
  })

  it('rejects a group- or other-writable root, where the parent alone lets a pack be swapped', async () => {
    const env = await scratchEnv()
    await installGrammarPack('python', env)
    // No permission on the files is needed: write on the parent is enough to
    // `rename` the pack away and put another directory in its place.
    await chmod(grammarDataDir(env), 0o775)

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toContain('writable by group or other')
  })

  it('rejects a group-writable pack directory too', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    await chmod(dir, 0o770)

    const state = await inspectGrammarPack('python', env)
    expect(state.status).toBe('failed')
    if (state.status !== 'failed') throw new Error('expected a failed pack')
    expect(state.reason).toContain('writable by group or other')
  })

  it('refuses to install through a pre-created symlinked root', async () => {
    const env = await scratchEnv()
    const root = grammarDataDir(env)
    const elsewhere = await mkdtemp(join(tmpdir(), 'codetruss-link-root-'))
    cleanup.push(elsewhere)
    await mkdir(dirname(root), { recursive: true })
    await symlink(elsewhere, root)

    await expect(installGrammarPack('python', env)).rejects.toThrow(/not a real directory/)
    // Nothing may land in the attacker's directory on the way to failing.
    await expect(readFile(join(elsewhere, 'tree-sitter.js'))).rejects.toThrow()
  })

  it('tightens a loose root on install rather than dead-ending the user', async () => {
    const env = await scratchEnv()
    const root = grammarDataDir(env)
    await mkdir(root, { recursive: true })
    await chmod(root, 0o755)

    await installGrammarPack('python', env)
    expect((await lstat(root)).mode & 0o777).toBe(0o700)
    await expect(inspectGrammarPack('python', env)).resolves.toMatchObject({ status: 'verified' })
  })
})

describe('uninstalling', () => {
  it('removes the pack and reports absence as the end state', async () => {
    const env = await scratchEnv()
    await installGrammarPack('python', env)
    await expect(uninstallGrammarPack('python', env)).resolves.toMatchObject({ removed: true })
    await expect(inspectGrammarPack('python', env)).resolves.toMatchObject({ status: 'absent' })
    // Already-absent is success: the requested end state holds.
    await expect(uninstallGrammarPack('python', env)).resolves.toMatchObject({ removed: false })
  })
})

describe('the pinned manifest', () => {
  it('pins a digest and a length for every artifact it will execute', () => {
    expect(PINNED_GRAMMAR_PACKS.length).toBeGreaterThan(0)
    for (const pack of PINNED_GRAMMAR_PACKS) {
      expect(pack.files.length).toBeGreaterThan(0)
      for (const file of pack.files) {
        expect(file.sha256).toMatch(/^[0-9a-f]{64}$/)
        expect(file.bytes).toBeGreaterThan(0)
        // Same-origin only: a third-party CDN is never a download target.
        expect(file.url.startsWith('/downloads/grammars/')).toBe(true)
      }
    }
  })

  it('matches the artifacts this repository publishes', async () => {
    for (const pack of PINNED_GRAMMAR_PACKS) {
      for (const file of pack.files) {
        const bytes = await readFile(join(publishedDir, `${pack.name}-${pack.version}`, file.name))
        expect(bytes.length).toBe(file.bytes)
      }
    }
  })

  it('derives the on-disk directory from the pack version, so packs coexist', () => {
    const pack = pinnedGrammarPack('python')!
    expect(grammarPackDir(pack, { XDG_DATA_HOME: '/data' }))
      .toBe(join('/data', 'codetruss', 'grammars', `python-${pack.version}`))
  })
})
