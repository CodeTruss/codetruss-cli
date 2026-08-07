/**
 * Gate: the site may not advertise a grammar pack it is not serving, and the
 * CLI may not ship a digest that no published artifact hashes to.
 *
 * Runs in the root `build` chain beside `cli:artifact:verify`. A checksum alone
 * would only prove the published file is internally consistent; this also
 * re-reads the upstream bytes out of `node_modules` and compares them, so a
 * pack cannot silently diverge from the runtime and grammar the hosted audit
 * loads. That equality is the entire basis for calling the two paths the same
 * analysis.
 */
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  GRAMMAR_PACKS,
  GRAMMAR_PACK_PROVENANCE,
  GRAMMAR_PACK_VERSION,
  packDirectoryName,
  packFileUrl,
} from './grammar-pack-sources.mjs'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const repoRoot = resolve(packageDir, '../..')

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export async function verifyGrammarPacks({
  grammarDir = join(repoRoot, 'public', 'downloads', 'grammars'),
  moduleDir = join(repoRoot, 'node_modules'),
  pinPath = join(packageDir, 'src', 'grammar-pack-manifest.ts'),
} = {}) {
  const manifestPacks = []

  for (const pack of GRAMMAR_PACKS) {
    const directoryName = packDirectoryName(pack)
    const packDir = join(grammarDir, directoryName)
    const files = []

    for (const file of pack.files) {
      let published
      try {
        published = await readFile(join(packDir, file.name))
      } catch (error) {
        if (error.code === 'ENOENT') {
          throw new Error(
            `grammar pack ${directoryName} is missing ${file.name}; run pnpm grammars:release`,
          )
        }
        throw error
      }

      // The published byte must be the byte the hosted audit loads. Comparing
      // digests of the published file against itself would prove nothing.
      const upstream = await readFile(join(moduleDir, ...file.source))
      if (!published.equals(upstream)) {
        throw new Error(
          `grammar pack ${directoryName}/${file.name} does not match ${file.source.join('/')} in node_modules; `
          + 'bump GRAMMAR_PACK_VERSION and run pnpm grammars:release',
        )
      }

      const digest = sha256(published)
      const sidecar = await readFile(`${join(packDir, file.name)}.sha256`, 'utf8')
      if (sidecar !== `${digest}  ${file.name}\n`) {
        throw new Error(`grammar pack ${directoryName}/${file.name}.sha256 does not match its artifact`)
      }
      files.push({ name: file.name, url: packFileUrl(pack, file.name), bytes: published.length, sha256: digest })
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

  const manifestPath = join(grammarDir, 'codetruss-grammars-latest.json')
  const manifest = await readFile(manifestPath, 'utf8')
  const expectedManifest = `${JSON.stringify({ packs: manifestPacks }, null, 2)}\n`
  if (manifest !== expectedManifest) {
    throw new Error('codetruss-grammars-latest.json does not match the published packs; run pnpm grammars:release')
  }

  // The CLI's compiled-in pin is the security boundary. If it disagrees with the
  // published artifact, either every install fails closed or — worse, if the pin
  // were stale in the other direction — the CLI would accept bytes nobody
  // reviewed. Neither may reach a build.
  const pin = await readFile(pinPath, 'utf8')
  for (const pack of manifestPacks) {
    for (const file of pack.files) {
      if (!pin.includes(`"sha256": "${file.sha256}"`)) {
        throw new Error(
          `src/grammar-pack-manifest.ts does not pin ${pack.name}-${pack.version}/${file.name}; `
          + 'run pnpm grammars:release',
        )
      }
    }
  }

  return manifestPacks
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const packs = await verifyGrammarPacks()
  for (const pack of packs) {
    process.stdout.write(`grammar pack ${pack.name}-${pack.version}: verified ${pack.files.length} artifacts\n`)
  }
}
