/**
 * Publish the opt-in tree-sitter grammar packs, and pin their digests into the CLI.
 *
 * Same discipline as `build-release.mjs`: a versioned artifact is written EXACTLY
 * once and never replaced, its sha256 is published beside it, and a manifest
 * records what the site is allowed to advertise. The difference is the consumer —
 * a CLI tarball is verified by a human running `shasum`, whereas a grammar pack
 * is verified by the CLI itself, on download and again on every load, against a
 * digest compiled into the binary. That pin is generated here
 * (`src/grammar-pack-manifest.ts`) so the published bytes and the expected bytes
 * cannot drift apart without this script being re-run.
 */
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  GRAMMAR_PACKS,
  GRAMMAR_PACK_PROVENANCE,
  GRAMMAR_PACK_VERSION,
  packDirectoryName,
  packFileUrl,
} from './grammar-pack-sources.mjs'
import { renderGrammarPin, renderGrammarSiteManifest } from './grammar-pack-render.mjs'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const repoRoot = resolve(packageDir, '../..')
const grammarDir = join(repoRoot, 'public', 'downloads', 'grammars')
const moduleDir = join(repoRoot, 'node_modules')

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

/**
 * Write a versioned artifact once, or prove the existing one already matches.
 *
 * A published pack file is immutable. Re-running the build is a no-op when the
 * bytes agree and a hard error when they do not, because a CLI already in the
 * field pins the old digest and would fail closed against replaced bytes.
 */
async function publishImmutable(path, bytes, label) {
  let published
  try {
    published = await readFile(path)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    await writeFile(path, bytes)
    return
  }
  if (!published.equals(bytes)) {
    throw new Error(
      `refusing to replace immutable ${label}: existing ${sha256(published)}, new ${sha256(bytes)}; `
      + 'bump GRAMMAR_PACK_VERSION in scripts/grammar-pack-sources.mjs',
    )
  }
}

const manifestPacks = []

for (const pack of GRAMMAR_PACKS) {
  const directoryName = packDirectoryName(pack)
  const packDir = join(grammarDir, directoryName)
  await mkdir(packDir, { recursive: true })

  const files = []
  for (const file of pack.files) {
    const bytes = await readFile(join(moduleDir, ...file.source))
    const digest = sha256(bytes)
    const target = join(packDir, file.name)
    await publishImmutable(target, bytes, `${directoryName}/${file.name}`)
    await writeFile(`${target}.sha256`, `${digest}  ${file.name}\n`, 'utf8')
    files.push({
      name: file.name,
      role: file.role,
      url: packFileUrl(pack, file.name),
      bytes: bytes.length,
      sha256: digest,
    })
  }

  // A stray file in a published pack directory is a supply-chain question, not
  // a tidiness one: the CLI installs whatever the manifest lists, but a reviewer
  // diffing the directory must not find bytes nobody accounted for.
  const present = (await readdir(packDir)).filter((name) => !name.endsWith('.sha256')).sort()
  const expected = pack.files.map((file) => file.name).sort()
  if (present.join('\n') !== expected.join('\n')) {
    throw new Error(`${directoryName} holds unexpected files: ${present.join(', ')}`)
  }

  manifestPacks.push({
    name: pack.name,
    version: GRAMMAR_PACK_VERSION,
    language: pack.language,
    runtime: GRAMMAR_PACK_PROVENANCE.runtime,
    grammar: GRAMMAR_PACK_PROVENANCE.grammar,
    files,
  })
}

export const GRAMMAR_MANIFEST_NAME = 'codetruss-grammars-latest.json'

// Both generated files come from one renderer, shared with the verifier, so the
// check that they are what this script would write today is a byte comparison
// rather than a re-implementation of the format.
await writeFile(join(grammarDir, GRAMMAR_MANIFEST_NAME), renderGrammarSiteManifest(manifestPacks), 'utf8')
await writeFile(join(packageDir, 'src', 'grammar-pack-manifest.ts'), renderGrammarPin(manifestPacks), 'utf8')

for (const pack of manifestPacks) {
  const total = pack.files.reduce((sum, file) => sum + file.bytes, 0)
  process.stdout.write(`grammar pack ${pack.name}-${pack.version}: ${pack.files.length} files, ${total} bytes\n`)
}
