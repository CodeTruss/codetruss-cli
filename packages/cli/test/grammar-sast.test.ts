import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { indexRepository } from '../src/indexer.js'
import { DEV_GRAMMAR_ORIGIN_ENV, installGrammarPack } from '../src/grammar-pack.js'
import { runLocalSast } from '../src/local-sast.js'

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
 * A repository holding one injectable Python module and one clean TS module.
 *
 * The Python here deliberately exercises classes the JS-family subset is
 * disclosed as NOT checking — command injection, path traversal, SSRF — because
 * that is the whole point of the pack: not "Python too", but "Python with the
 * rules the local JS pass cannot run".
 */
async function pythonRepo(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-grammar-sast-'))
  cleanup.push(root)
  await mkdir(join(root, 'app'))
  await writeFile(join(root, 'app', 'views.py'), [
    'import os',
    'import requests',
    'from flask import request',
    '',
    '',
    'def run_cmd():',
    '    name = request.args.get("name")',
    '    os.system("ls " + name)',
    '',
    '',
    'def read_file():',
    '    p = request.args.get("p")',
    '    return open("/data/" + p).read()',
    '',
    '',
    'def fetch():',
    '    url = request.args.get("url")',
    '    return requests.get(url).text',
    '',
    '',
    '# The DB-API two-step: the cursor is a short local, not a DB-ish name.',
    'def get_user(conn):',
    '    user_id = request.args.get("id")',
    '    cur = conn.cursor()',
    '    cur.execute("SELECT * FROM users WHERE id = " + user_id)',
    '    return cur.fetchall()',
    '',
  ].join('\n'))
  await writeFile(join(root, 'app', 'clean.ts'), 'export const a = 1\n')
  return root
}

/**
 * An environment whose grammar data directory is a throwaway temp dir on EVERY
 * platform.
 *
 * This returns the whole env rather than the directory so that callers cannot
 * spell the isolation themselves and get it half right: `grammarDataDir` reads
 * LOCALAPPDATA on Windows and XDG_DATA_HOME everywhere else, and naming only one
 * of them isolates only one platform. The tests below install a pack and then
 * corrupt it, so the platform that misses out does not merely leak state — it
 * leaves a tampered pack in the developer's real data directory.
 */
async function scratchDataEnv(): Promise<NodeJS.ProcessEnv> {
  const home = await mkdtemp(join(tmpdir(), 'codetruss-grammar-data-'))
  cleanup.push(home)
  return { XDG_DATA_HOME: home, LOCALAPPDATA: home }
}

describe('the local pass without a grammar pack', () => {
  it('skips Python, analyzes nothing there, and records why', async () => {
    const root = await pythonRepo()
    const env = await scratchDataEnv()
    const result = await runLocalSast(await indexRepository(root), env)

    expect(result.findings).toHaveLength(0)
    const metrics = result.pass.result.metrics!
    expect(metrics.pythonPackStatus).toBe('absent')
    expect(metrics.pythonFiles).toBe(1)
    expect(metrics.pythonFilesScanned).toBe(0)
    // Skipping a language is not a failure of the pass: it is disclosed
    // coverage, and a clean JS/TS repo must still be able to reach PASS.
    expect(result.pass.result.complete).toBe(true)
    expect(result.pass.error).toBeUndefined()
  })

  it('says nothing about Python for a repository that has none', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-no-python-'))
    cleanup.push(root)
    await mkdir(join(root, 'src'))
    await writeFile(join(root, 'src', 'a.ts'), 'export const a = 1\n')
    const env = await scratchDataEnv()

    const result = await runLocalSast(await indexRepository(root), env)
    expect(result.pass.result.metrics!.pythonPackStatus).toBe('not-applicable')
    expect(result.pass.result.metrics!.pythonFiles).toBe(0)
  })
})

describe('the local pass with the grammar pack installed', () => {
  it('finds Python injection the JS parser could never reach', async () => {
    const root = await pythonRepo()
    const env = { ...await scratchDataEnv(), [DEV_GRAMMAR_ORIGIN_ENV]: origin }
    await installGrammarPack('python', env)

    const result = await runLocalSast(await indexRepository(root), env)
    const metrics = result.pass.result.metrics!
    expect(metrics.pythonPackStatus).toBe('verified')
    expect(metrics.pythonFilesScanned).toBe(1)

    // The Python scan runs the FULL pack, not the JS subset. Each of these is a
    // class the JS-family pass is explicitly disclosed as not checking, so their
    // presence is the pack doing the thing it exists for.
    const rules = result.findings.map((finding) => finding.metadata?.ruleId)
    expect(rules).toContain('command-injection')
    expect(rules).toContain('path-traversal')
    expect(rules).toContain('ssrf')
    expect(rules).toContain('sql-injection')
    for (const finding of result.findings) {
      expect(finding.analyzerId).toBe('local-sast')
      expect(finding.filePath).toBe('app/views.py')
    }
  })

  /**
   * A single `codetruss review` analyzes twice — the baseline tree, then the
   * final tree — so the pack is loaded twice in one process. The emscripten
   * runtime reassigns its own `module.exports` during init, so a naive second
   * `require()` returns the Module object instead of the Parser class and the
   * whole second analysis silently loses Python. That failure is invisible to a
   * one-shot test and to the receipt, which would just say "not analyzed".
   */
  it('analyzes Python on a second load in the same process', async () => {
    const root = await pythonRepo()
    const env = { ...await scratchDataEnv(), [DEV_GRAMMAR_ORIGIN_ENV]: origin }
    await installGrammarPack('python', env)
    const index = await indexRepository(root)

    const first = await runLocalSast(index, env)
    const second = await runLocalSast(index, env)

    expect(second.pass.result.metrics!.pythonPackStatus).toBe('verified')
    expect(second.pass.result.metrics!.pythonFilesScanned).toBe(1)
    // The baseline and final analyses must see the same code the same way, or
    // the finding delta is computed against a tree that was never analyzed.
    expect(second.findings.map((finding) => finding.metadata?.ruleId).sort())
      .toEqual(first.findings.map((finding) => finding.metadata?.ruleId).sort())
  })

  it('refuses to analyze Python with a tampered pack, and says so', async () => {
    const root = await pythonRepo()
    const env = { ...await scratchDataEnv(), [DEV_GRAMMAR_ORIGIN_ENV]: origin }
    const { dir } = await installGrammarPack('python', env)
    const target = join(dir, 'tree-sitter.js')
    await writeFile(target, `${await readFile(target, 'utf8')}\n// injected`)

    const result = await runLocalSast(await indexRepository(root), env)
    const metrics = result.pass.result.metrics!
    expect(metrics.pythonPackStatus).toBe('failed')
    expect(metrics.pythonFilesScanned).toBe(0)
    expect(String(metrics.pythonPackReason)).toContain('tree-sitter.js')
    // WHICH failure, so the receipt can avoid accusing a healthy install of
    // tampering when the real problem was the runtime or the scan.
    expect(metrics.pythonPackFailureKind).toBe('digest')
    // Nothing was executed from the modified pack, so no Python finding exists.
    expect(result.findings.filter((finding) => finding.filePath?.endsWith('.py'))).toHaveLength(0)
  })
})
