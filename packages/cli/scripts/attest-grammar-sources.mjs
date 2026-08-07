/**
 * Prove a grammar pack's upstream bytes against something other than this
 * machine's `node_modules`.
 *
 * The offline gate (`verify-grammar-packs.mjs`) chains published artifact →
 * `node_modules` → generated pin, which is an internal-consistency proof: one
 * compromised `node_modules` on the release machine poisons the artifact, the
 * pin AND the verifier in a single move, and every check still passes. This
 * script is the missing link at the top of that chain. It takes the tarball
 * digest the workspace lockfile recorded at install time, confirms the registry
 * still serves that exact digest for that version, verifies the registry's
 * signature over the pair, downloads the tarball, checks it hashes to the same
 * digest, and compares the files inside it against what the build script would
 * read out of `node_modules`.
 *
 * What that establishes, precisely: the bytes this release publishes are the
 * bytes npm signed for the versions the lockfile pins. What it does not: it runs
 * on the release machine, so a compromise deep enough to patch this script is
 * not caught by this script. The point is to close the cheap window — a poisoned
 * file dropped into `node_modules` — not to claim a reproducible build.
 *
 * Network, therefore release-time and not a build gate: `pnpm build` must not
 * depend on npm being reachable. Run by `pnpm grammars:release` before anything
 * is published, and standalone with `pnpm grammars:attest`.
 */
import { readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { GRAMMAR_PACKS, GRAMMAR_PACK_PROVENANCE } from './grammar-pack-sources.mjs'
import { lockedSourcePackage } from './lockfile-integrity.mjs'
import { readTarballMembers, subresourceIntegrity, verifyRegistrySignature } from './npm-tarball.mjs'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const repoRoot = resolve(packageDir, '../..')
const REGISTRY = 'https://registry.npmjs.org'
const NETWORK_TIMEOUT_MS = 60_000

async function fetchJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS) })
  if (!response.ok) throw new Error(`${url} responded ${response.status}`)
  return response.json()
}

async function fetchBytes(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS) })
  if (!response.ok) throw new Error(`${url} responded ${response.status}`)
  return Buffer.from(await response.arrayBuffer())
}

export async function attestGrammarSources({
  moduleDir = join(repoRoot, 'node_modules'),
  lockfilePath = join(repoRoot, 'pnpm-lock.yaml'),
  registry = REGISTRY,
} = {}) {
  const lockfile = await readFile(lockfilePath, 'utf8')
  const keys = (await fetchJson(`${registry}/-/npm/v1/keys`)).keys ?? []
  const attested = []

  for (const source of Object.values(GRAMMAR_PACK_PROVENANCE)) {
    const { package: name, version } = source
    const locked = lockedSourcePackage(lockfile, name, version)

    const metadata = await fetchJson(`${registry}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`)
    const dist = metadata.dist ?? {}
    // The lockfile is the anchor, not the registry: if they disagree, this
    // workspace installed something the registry no longer serves under that
    // version, which is exactly the event worth stopping a release for.
    if (dist.integrity !== locked.integrity) {
      throw new Error(
        `${name}@${version}: pnpm-lock.yaml records ${locked.integrity} but the registry serves ${dist.integrity}`,
      )
    }
    const [signature] = dist.signatures ?? []
    if (!signature) throw new Error(`${name}@${version} carries no registry signature`)
    verifyRegistrySignature({ name, version, integrity: dist.integrity, signature, keys })

    const tarball = await fetchBytes(dist.tarball)
    const downloaded = subresourceIntegrity(tarball)
    if (downloaded !== locked.integrity) {
      throw new Error(`${dist.tarball} hashes to ${downloaded}, expected ${locked.integrity}`)
    }
    attested.push({ name, version, integrity: locked.integrity, members: readTarballMembers(tarball) })
  }

  const files = []
  for (const pack of GRAMMAR_PACKS) {
    for (const file of pack.files) {
      const [sourcePackage, ...rest] = file.source
      const upstream = attested.find((entry) => entry.name === sourcePackage)
      if (!upstream) {
        throw new Error(`${pack.name}/${file.name} is cut from ${sourcePackage}, which has no provenance entry`)
      }
      const member = upstream.members.get(['package', ...rest].join('/'))
      if (!member) {
        throw new Error(
          `${sourcePackage}@${upstream.version} does not contain ${rest.join('/')}; `
          + 'the pack source path is wrong or the tarball layout changed',
        )
      }
      const installed = await readFile(join(moduleDir, ...file.source))
      if (!member.equals(installed)) {
        throw new Error(
          `node_modules/${file.source.join('/')} does not match the signed ${sourcePackage}@${upstream.version} `
          + 'tarball; do not publish from this checkout until that is explained',
        )
      }
      files.push({
        name: file.name,
        source: `${sourcePackage}@${upstream.version}`,
        sha256: createHash('sha256').update(member).digest('hex'),
      })
    }
  }

  return { sources: attested.map(({ name, version, integrity }) => ({ name, version, integrity })), files }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const result = await attestGrammarSources()
  for (const source of result.sources) {
    process.stdout.write(`attested ${source.name}@${source.version} against its signed registry tarball\n`)
  }
  for (const file of result.files) {
    process.stdout.write(`  ${file.name}: ${file.sha256} (from ${file.source})\n`)
  }
}
