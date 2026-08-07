/**
 * Gate: the site may not advertise a grammar pack it is not serving, and the
 * CLI may not ship a pin that is not exactly what the published artifacts
 * generate.
 *
 * Runs in the root `build` chain beside `cli:artifact:verify`. A checksum alone
 * would only prove the published file is internally consistent; this also
 * re-reads the upstream bytes out of `node_modules` and compares them, so a
 * pack cannot silently diverge from the runtime and grammar the hosted audit
 * loads. That equality is the entire basis for calling the two paths the same
 * analysis.
 *
 * The two GENERATED files are compared whole, against the same renderer that
 * writes them. Matching expected substrings instead — the shape this check used
 * to have — proves only that each digest appears somewhere in the pin: it says
 * nothing about which file name a digest is bound to, and nothing at all about
 * entries the pin contains that nobody published. A hand-edited pin carrying the
 * three real digests plus a fourth artifact passed that check.
 *
 * What this gate does NOT establish is stated plainly in `SECURITY.md`: it reads
 * `node_modules` on the same machine that produced both the artifact and the
 * pin, so it is an internal-consistency proof, not an independent one. The
 * independent check — upstream tarball, registry signature, lockfile integrity —
 * needs the network and lives in `attest-grammar-sources.mjs`.
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
import { GRAMMAR_FILE_ROLES, renderGrammarPin, renderGrammarSiteManifest } from './grammar-pack-render.mjs'
import { lockedSourcePackage } from './lockfile-integrity.mjs'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const repoRoot = resolve(packageDir, '../..')

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

/**
 * Every artifact says what the loader should do with it, exactly once.
 *
 * The loader refuses a pack that declares two grammars, but it should never see
 * one: this is the hand-edited file where such a pack would be introduced.
 */
function assertRoles(pack, directoryName) {
  for (const file of pack.files) {
    if (!GRAMMAR_FILE_ROLES.includes(file.role)) {
      throw new Error(`${directoryName}/${file.name} declares unknown role ${JSON.stringify(file.role)}`)
    }
  }
  for (const role of GRAMMAR_FILE_ROLES) {
    const named = pack.files.filter((file) => file.role === role).map((file) => file.name)
    if (named.length !== 1) {
      throw new Error(
        `${directoryName} declares ${named.length} artifacts for role ${role}`
        + `${named.length ? ` (${named.join(', ')})` : ''}; exactly one is required`,
      )
    }
  }
}

export async function verifyGrammarPacks({
  grammarDir = join(repoRoot, 'public', 'downloads', 'grammars'),
  moduleDir = join(repoRoot, 'node_modules'),
  pinPath = join(packageDir, 'src', 'grammar-pack-manifest.ts'),
  lockfilePath = join(repoRoot, 'pnpm-lock.yaml'),
} = {}) {
  // The provenance a pack claims must be the version this workspace actually
  // installs, or the pack's own description of where its bytes came from is
  // unchecked prose.
  const lockfile = await readFile(lockfilePath, 'utf8')
  for (const source of Object.values(GRAMMAR_PACK_PROVENANCE)) {
    lockedSourcePackage(lockfile, source.package, source.version)
  }

  const manifestPacks = []

  for (const pack of GRAMMAR_PACKS) {
    const directoryName = packDirectoryName(pack)
    const packDir = join(grammarDir, directoryName)
    assertRoles(pack, directoryName)
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
      files.push({
        name: file.name,
        role: file.role,
        url: packFileUrl(pack, file.name),
        bytes: published.length,
        sha256: digest,
      })
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

  const manifest = await readFile(join(grammarDir, 'codetruss-grammars-latest.json'), 'utf8')
  if (manifest !== renderGrammarSiteManifest(manifestPacks)) {
    throw new Error('codetruss-grammars-latest.json does not match the published packs; run pnpm grammars:release')
  }

  // The CLI's compiled-in pin is the security boundary. If it disagrees with the
  // published artifacts, either every install fails closed or — worse, if the
  // pin were wrong in the other direction — the CLI would accept bytes nobody
  // reviewed. Whole-file, because every part of this file is load-bearing: the
  // digests, the names they are bound to, the URLs they are fetched from, the
  // roles the loader selects on, and the lookup function underneath them.
  const pin = await readFile(pinPath, 'utf8')
  const expectedPin = renderGrammarPin(manifestPacks)
  if (pin !== expectedPin) {
    throw new Error(
      'src/grammar-pack-manifest.ts is not what the published grammar packs generate '
      + `(${sha256(pin)} vs ${sha256(expectedPin)}); it is generated, not hand-written — run pnpm grammars:release`,
    )
  }

  return manifestPacks
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const packs = await verifyGrammarPacks()
  for (const pack of packs) {
    process.stdout.write(`grammar pack ${pack.name}-${pack.version}: verified ${pack.files.length} artifacts\n`)
  }
}
