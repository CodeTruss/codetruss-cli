import { createServer, type Server } from 'node:http'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { DEV_GRAMMAR_ORIGIN_ENV, installGrammarPack } from '../src/grammar-pack.js'
import { runGrammarsCommand } from '../src/grammar-command.js'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const publishedDir = join(repoRoot, 'public', 'downloads', 'grammars')

const cleanup: string[] = []
afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

let server: Server
let origin: string

beforeAll(async () => {
  server = createServer((req, res) => {
    const path = decodeURIComponent((req.url ?? '').split('?')[0])
    const prefix = '/downloads/grammars/'
    if (!path.startsWith(prefix) || path.includes('..')) {
      res.writeHead(404).end()
      return
    }
    readFile(join(publishedDir, path.slice(prefix.length))).then(
      (bytes) => res.writeHead(200).end(bytes),
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

/**
 * LOCALAPPDATA as well as XDG_DATA_HOME: `grammarDataDir` reads the former on
 * Windows and the latter everywhere else, so setting one alone leaves the suite
 * reading and writing the developer's real pack directory on the other platform.
 */
async function scratchEnv(): Promise<NodeJS.ProcessEnv> {
  const home = await mkdtemp(join(tmpdir(), 'codetruss-grammars-cmd-'))
  cleanup.push(home)
  return { XDG_DATA_HOME: home, LOCALAPPDATA: home, [DEV_GRAMMAR_ORIGIN_ENV]: origin }
}

function capture() {
  const chunks: string[] = []
  return { write: (text: string) => { chunks.push(text) }, get text() { return chunks.join('') } }
}

describe('codetruss grammars', () => {
  it('lists what can be installed, with its provenance and size', async () => {
    const out = capture()
    expect(await runGrammarsCommand('list', undefined, out.write, await scratchEnv())).toBe(0)
    expect(out.text).toContain('python-1.0.0')
    // A user deciding whether to download 700 KB of WASM deserves to see what
    // it is and where it came from before they run the command.
    expect(out.text).toContain('web-tree-sitter@0.22.6')
    expect(out.text).toContain('tree-sitter-wasms@0.1.11')
    expect(out.text).toContain('codetruss grammars install python')
  })

  it('reports an uninstalled pack as a disclosed gap, and exits non-zero', async () => {
    const out = capture()
    expect(await runGrammarsCommand('status', undefined, out.write, await scratchEnv())).toBe(1)
    expect(out.text).toContain('not installed')
    expect(out.text).toContain('skipped locally and disclosed as such')
  })

  it('installs, then reports verified', async () => {
    const env = await scratchEnv()
    const install = capture()
    expect(await runGrammarsCommand('install', 'python', install.write, env)).toBe(0)
    expect(install.text).toContain('Installed python-1.0.0')
    expect(install.text).toContain('matched the SHA-256 pinned in this CLI')

    const status = capture()
    expect(await runGrammarsCommand('status', undefined, status.write, env)).toBe(0)
    expect(status.text).toContain('installed and verified')
  })

  it('shouts about a tampered pack rather than reporting it as merely missing', async () => {
    const env = await scratchEnv()
    const { dir } = await installGrammarPack('python', env)
    await writeFile(join(dir, 'tree-sitter.wasm'), Buffer.alloc(4))

    const out = capture()
    expect(await runGrammarsCommand('status', undefined, out.write, env)).toBe(1)
    expect(out.text).toContain('FAILED VERIFICATION')
    expect(out.text).toContain('not loaded')
  })

  it('uninstalls and says what that costs', async () => {
    const env = await scratchEnv()
    await installGrammarPack('python', env)
    const out = capture()
    expect(await runGrammarsCommand('uninstall', 'python', out.write, env)).toBe(0)
    expect(out.text).toContain('python is skipped locally again')
  })

  it('rejects an unknown action instead of doing nothing quietly', async () => {
    await expect(runGrammarsCommand('frobnicate', undefined, capture().write, await scratchEnv()))
      .rejects.toThrow(/list, status, install, or uninstall/)
  })

  it('requires a pack name for install', async () => {
    await expect(runGrammarsCommand('install', undefined, capture().write, await scratchEnv()))
      .rejects.toThrow(/requires a pack name/)
  })
})
