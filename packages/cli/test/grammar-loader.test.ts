import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  pinnedGrammarPack,
  type PinnedGrammarFile,
  type PinnedGrammarPack,
} from '../src/grammar-pack-manifest.js'
import type { GrammarPackState } from '../src/grammar-pack.js'

/**
 * What the loader EXECUTES, as opposed to what the inspector verified.
 *
 * These tests stub the inspection so the two can be told apart: the state names
 * a directory holding a hostile payload while carrying the genuine verified
 * buffers. A loader that re-opens the path to execute it runs the payload; a
 * loader that executes the buffers it was handed cannot. That distinction is
 * the entire security position of the grammar pack, and nothing about it is
 * observable when verification and execution both read the same healthy file.
 */
const stub = vi.hoisted(() => ({ current: null as GrammarPackState | null }))

vi.mock('../src/grammar-pack.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/grammar-pack.js')>()
  return {
    ...actual,
    inspectGrammarPack: async (name: string, env?: NodeJS.ProcessEnv) => (
      stub.current ?? actual.inspectGrammarPack(name, env)
    ),
  }
})

const { loadGrammarParser } = await import('../src/grammar-parser.js')

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const pack = pinnedGrammarPack('python')!
const publishedPack = join(repoRoot, 'public', 'downloads', 'grammars', `${pack.name}-${pack.version}`)

const cleanup: string[] = []
afterEach(async () => {
  stub.current = null
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

/** The real published bytes, as `inspectGrammarPack` would have returned them. */
async function verifiedContents(): Promise<Map<string, Buffer>> {
  const contents = new Map<string, Buffer>()
  for (const file of pack.files) contents.set(file.name, await readFile(join(publishedPack, file.name)))
  return contents
}

async function scratchDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'codetruss-loader-'))
  cleanup.push(dir)
  return dir
}

describe('the loader executes verified bytes, never a path', () => {
  /**
   * The adversarial review's proof-of-concept in deterministic form: the pack
   * directory holds a module that writes a marker file and exports nothing
   * usable, while the state carries the genuine buffers. Against a loader that
   * does `createRequire(runtimePath)(runtimePath)` this writes the marker and
   * owns the process. Against this one the payload is unreachable.
   */
  it('parses Python from the buffers even when every file on disk is a payload', async () => {
    const dir = await scratchDir()
    const marker = join(dir, 'PWNED')
    await writeFile(
      join(dir, 'tree-sitter.js'),
      `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'pwned')\nmodule.exports = {}\n`,
    )
    await writeFile(join(dir, 'tree-sitter.wasm'), Buffer.from('not wasm'))
    await writeFile(join(dir, 'tree-sitter-python.wasm'), Buffer.from('not wasm'))

    stub.current = { status: 'verified', pack, dir, contents: await verifiedContents() }
    const load = await loadGrammarParser('python')

    expect(load.status).toBe('verified')
    if (load.status !== 'verified') throw new Error('expected a verified load')
    const tree = await load.parser.parse('python', 'import os\nos.system(name)\n')
    expect(tree).not.toBeNull()
    expect(tree!.hasError).toBe(false)
    tree!.release()
    // The single fact this whole design exists to guarantee.
    expect(existsSync(marker)).toBe(false)
  })

  it('loads with nothing at the pack path at all', async () => {
    const dir = await scratchDir()
    // Deleting the directory between verification and execution is the same
    // race with the timing removed: the load must not notice.
    await rm(dir, { recursive: true, force: true })

    stub.current = { status: 'verified', pack, dir, contents: await verifiedContents() }
    const load = await loadGrammarParser('python')
    expect(load.status).toBe('verified')
  })
})

/**
 * Which artifact is the grammar is a question the pin answers explicitly.
 *
 * It used to be answered by `files.find(f => f.name.startsWith('tree-sitter-'))`
 * — the first match — while the pin verifier only proved that each published
 * digest appeared SOMEWHERE in the generated file. The two together meant a pin
 * with an extra entry ordered ahead of the real grammar passed review and was
 * loaded instead of it.
 */
describe('the grammar is selected by role, not by name shape', () => {
  it('ignores an injected artifact that would have won the old name-prefix match', async () => {
    const dir = await scratchDir()
    const contents = await verifiedContents()
    contents.set('tree-sitter-evil.wasm', Buffer.from('not wasm'))
    const injected: PinnedGrammarPack = {
      ...pack,
      files: [
        // No role, because the generated pin had no such field when this shape
        // was hand-editable — and ordered first, matching `tree-sitter-`, which
        // is exactly what the old `find` resolved as the grammar.
        {
          name: 'tree-sitter-evil.wasm',
          url: '/downloads/grammars/python-1.0.0/tree-sitter-evil.wasm',
          bytes: 8,
          sha256: 'a'.repeat(64),
        } as PinnedGrammarFile,
        ...pack.files,
      ],
    }

    stub.current = { status: 'verified', pack: injected, dir, contents }
    const load = await loadGrammarParser('python')

    // Against the old loader the injected file is the grammar, `Language.load`
    // is handed `not wasm`, and this is a runtime failure instead.
    expect(load.status).toBe('verified')
    if (load.status !== 'verified') throw new Error('expected a verified load')
    const tree = await load.parser.parse('python', 'import os\nos.system(name)\n')
    expect(tree).not.toBeNull()
    expect(tree!.hasError).toBe(false)
    tree!.release()
  })

  it('refuses a pack that declares two grammars rather than loading the first', async () => {
    const dir = await scratchDir()
    const contents = await verifiedContents()
    contents.set('tree-sitter-evil.wasm', Buffer.from('not wasm'))
    const ambiguous: PinnedGrammarPack = {
      ...pack,
      files: [
        {
          name: 'tree-sitter-evil.wasm',
          role: 'grammar',
          url: '/downloads/grammars/python-1.0.0/tree-sitter-evil.wasm',
          bytes: 8,
          sha256: 'a'.repeat(64),
        },
        ...pack.files,
      ],
    }

    stub.current = { status: 'verified', pack: ambiguous, dir, contents }
    const load = await loadGrammarParser('python')

    // A malformed pin is this binary's defect, not the user's install, so it
    // must not render the receipt sentence that accuses their pack of tampering.
    expect(load).toMatchObject({ status: 'failed', kind: 'runtime' })
    if (load.status !== 'failed') throw new Error('expected a failed load')
    expect(load.reason).toContain('role grammar')
  })
})

describe('why a pack was unusable is carried, not collapsed', () => {
  it('calls a pack that failed inspection a digest failure', async () => {
    const dir = await scratchDir()
    stub.current = {
      status: 'failed',
      pack,
      dir,
      reason: 'tree-sitter.js has digest deadbeef, expected ddcacb69',
    }
    const load = await loadGrammarParser('python')
    expect(load).toMatchObject({ status: 'failed', kind: 'digest' })
  })

  /**
   * The failure the review cared about: every digest matched and the runtime
   * still would not start. An OOM inside emscripten must never be published as
   * an accusation that the user's pack does not match the pinned digests.
   */
  it('calls a verified pack whose runtime will not start a runtime failure', async () => {
    const dir = await scratchDir()
    const contents = await verifiedContents()
    contents.set('tree-sitter.js', Buffer.from('module.exports = {}\n'))

    stub.current = { status: 'verified', pack, dir, contents }
    const load = await loadGrammarParser('python')
    expect(load).toMatchObject({ status: 'failed', kind: 'runtime' })
    if (load.status !== 'failed') throw new Error('expected a failed load')
    expect(load.reason).not.toContain('digest')
  })
})
