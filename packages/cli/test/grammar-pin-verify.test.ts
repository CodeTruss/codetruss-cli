import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { PINNED_GRAMMAR_PACKS } from '../src/grammar-pack-manifest.js'
import { lockedSourcePackage, lockfileEntries } from '../scripts/lockfile-integrity.mjs'
import { verifyGrammarPacks } from '../scripts/verify-grammar-packs.mjs'

/**
 * `pnpm grammars:verify` is the gate a hand-edited pin has to get past.
 *
 * The pin is generated and says so, which makes it exactly the file a reviewer
 * skims. Everything the CLI will download and execute is described there, so the
 * gate has to prove the whole file is what the published artifacts generate —
 * not that each digest turns up somewhere inside it.
 */
const packageDir = join(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = join(packageDir, '..', '..')
const realPinPath = join(packageDir, 'src', 'grammar-pack-manifest.ts')
const realLockfilePath = join(repoRoot, 'pnpm-lock.yaml')

const cleanup: string[] = []
afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function scratchFile(name: string, contents: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'codetruss-pin-'))
  cleanup.push(dir)
  const path = join(dir, name)
  await writeFile(path, contents, 'utf8')
  return path
}

/**
 * The check this gate used to perform, kept here as the thing being disproved.
 *
 * Every assertion below that a tampered pin is rejected is paired with the
 * observation that this returned true for it — otherwise "the new check fails on
 * a bad pin" would not tell anyone whether the old one did too.
 */
function oldSubstringCheck(pin: string): boolean {
  return PINNED_GRAMMAR_PACKS.every((pack) => (
    pack.files.every((file) => pin.includes(`"sha256": "${file.sha256}"`))
  ))
}

describe('the compiled-in pin is verified whole, not sampled', () => {
  it('accepts the pin this repository actually ships', async () => {
    const packs = await verifyGrammarPacks()
    expect(packs).toHaveLength(PINNED_GRAMMAR_PACKS.length)
    expect(packs[0].files.map((file) => file.role)).toEqual(['runtime', 'runtime-wasm', 'grammar'])
  })

  it('rejects a fourth artifact added beside the three real digests', async () => {
    // F8's bypass verbatim: keep every published digest, add an entry nobody
    // published, and order it where the old name-prefix loader would pick it up
    // as the grammar. The pack directory check would then demand the extra file
    // be present, and the CLI would download and load it.
    const real = await readFile(realPinPath, 'utf8')
    const injected = [
      '      {',
      '        "name": "tree-sitter-evil.wasm",',
      '        "role": "grammar",',
      '        "url": "/downloads/grammars/python-1.0.0/tree-sitter-evil.wasm",',
      '        "bytes": 8,',
      `        "sha256": "${'a'.repeat(64)}"`,
      '      },',
      '',
    ].join('\n')
    const tampered = real.replace('    "files": [\n', `    "files": [\n${injected}`)
    expect(tampered).not.toBe(real)
    expect(oldSubstringCheck(tampered)).toBe(true)

    await expect(verifyGrammarPacks({ pinPath: await scratchFile('pin.ts', tampered) }))
      .rejects.toThrow(/not what the published grammar packs generate/)
  })

  it('rejects digests bound to the wrong file name', async () => {
    // Both real digests are still present — they have simply swapped artifacts,
    // so the CLI would demand the runtime hash from the WASM and vice versa.
    const real = await readFile(realPinPath, 'utf8')
    const [runtime, runtimeWasm] = PINNED_GRAMMAR_PACKS[0].files
    const swapped = real
      .replace(runtime.sha256, 'PLACEHOLDER')
      .replace(runtimeWasm.sha256, runtime.sha256)
      .replace('PLACEHOLDER', runtimeWasm.sha256)
    expect(swapped).not.toBe(real)
    expect(oldSubstringCheck(swapped)).toBe(true)

    await expect(verifyGrammarPacks({ pinPath: await scratchFile('pin.ts', swapped) }))
      .rejects.toThrow(/not what the published grammar packs generate/)
  })

  it('rejects a hand edit below the digests, where a skimming reviewer stops', async () => {
    // Nothing about the digests changes; `pinnedGrammarPack` simply stops being
    // a lookup. The old check read the array and never looked at the code.
    const real = await readFile(realPinPath, 'utf8')
    const rewritten = real.replace(
      'return PINNED_GRAMMAR_PACKS.find((pack) => pack.name === name)',
      'return PINNED_GRAMMAR_PACKS[0]',
    )
    expect(rewritten).not.toBe(real)
    expect(oldSubstringCheck(rewritten)).toBe(true)

    await expect(verifyGrammarPacks({ pinPath: await scratchFile('pin.ts', rewritten) }))
      .rejects.toThrow(/not what the published grammar packs generate/)
  })
})

/**
 * The provenance strings are a claim about where a pack's bytes came from, and
 * until they were checked against the lockfile they were only a comment: a
 * dependency bump with a stale string published a pack that misidentified its
 * own source, and nothing failed.
 */
describe('pack provenance is checked against the workspace lockfile', () => {
  it('rejects a lockfile that pins a different version than the pack claims', async () => {
    const lockfile = [
      'packages:',
      '',
      '  web-tree-sitter@0.99.0:',
      '    resolution: {integrity: sha512-AAAA==}',
      '',
      '  tree-sitter-wasms@0.1.11:',
      '    resolution: {integrity: sha512-BBBB==}',
      '',
    ].join('\n')

    await expect(verifyGrammarPacks({ lockfilePath: await scratchFile('pnpm-lock.yaml', lockfile) }))
      .rejects.toThrow(/web-tree-sitter@0.22.6 but pnpm-lock.yaml pins web-tree-sitter@0.99.0/)
  })

  it('reads the integrity of a single-version dependency out of the real lockfile', async () => {
    const lockfile = await readFile(realLockfilePath, 'utf8')
    const entry = lockedSourcePackage(lockfile, 'web-tree-sitter', '0.22.6')
    expect(entry.integrity).toMatch(/^sha512-/)
    // Scoped names split at the version, not at the scope.
    expect(lockfileEntries(lockfile, '@types/node').length).toBeGreaterThan(0)
  })

  it('refuses to guess when a dependency resolves to two versions', () => {
    const lockfile = [
      'packages:',
      '',
      '  web-tree-sitter@0.22.6:',
      '    resolution: {integrity: sha512-AAAA==}',
      '',
      '  web-tree-sitter@0.23.0:',
      '    resolution: {integrity: sha512-BBBB==}',
      '',
    ].join('\n')
    expect(() => lockedSourcePackage(lockfile, 'web-tree-sitter', '0.22.6')).toThrow(/2 versions/)
  })
})
