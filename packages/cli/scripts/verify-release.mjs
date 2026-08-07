import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { assertReleasePackagePolicy } from './release-package-policy.mjs'
import { buildReleaseManifest, serialiseReleaseManifest } from './release-metadata.mjs'
import { cycloneDxSerialNumber } from './generate-sbom.mjs'
import { verifyDeterministicPackageArchive } from './verify-deterministic-package.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const defaultPackageDir = resolve(dirname(scriptPath), '..')
const defaultDownloadDir = join(resolve(defaultPackageDir, '../..'), 'public', 'downloads')
const digest = (value) => createHash('sha256').update(value).digest('hex')

export async function verifyRelease({ packageDir = defaultPackageDir, downloadDir = defaultDownloadDir } = {}) {
  const pkgBytes = await readFile(join(packageDir, 'package.json'))
  const pkg = JSON.parse(pkgBytes.toString('utf8'))
  assertReleasePackagePolicy(pkg)
  const versionedName = `codetruss-cli-${pkg.version}.tgz`
  const latestName = 'codetruss-cli-latest.tgz'
  const versionedSbomName = `codetruss-cli-${pkg.version}.sbom.cdx.json`
  const versioned = await readFile(join(downloadDir, versionedName))
  const latest = await readFile(join(downloadDir, latestName))
  const versionedSbom = await readFile(join(downloadDir, versionedSbomName))
  const latestSbom = await readFile(join(downloadDir, 'codetruss-cli-latest.sbom.cdx.json'))
  const versionedSha = digest(versioned)
  const sbomSha = digest(versionedSbom)
  const expectedMetadata = buildReleaseManifest({ pkg, sha256: versionedSha, sbomSha256: sbomSha })
  const metadataBytes = await readFile(join(downloadDir, 'codetruss-cli-latest.json'))
  const expectedMetadataBytes = Buffer.from(serialiseReleaseManifest(expectedMetadata), 'utf8')
  if (!metadataBytes.equals(expectedMetadataBytes)) {
    throw new Error(`release metadata is not the canonical manifest for CLI ${pkg.version}; run pnpm cli:release`)
  }
  if (!latest.equals(versioned)) throw new Error(`${latestName} does not match immutable ${versionedName}`)
  if (!latestSbom.equals(versionedSbom)) throw new Error(`latest release SBOM does not match ${versionedSbomName}`)

  const expectedSidecars = new Map([
    [`${versionedName}.sha256`, `${versionedSha}  ${versionedName}\n`],
    [`${latestName}.sha256`, `${versionedSha}  ${latestName}\n`],
  ])
  for (const [name, expected] of expectedSidecars) {
    const sidecar = await readFile(join(downloadDir, name), 'utf8')
    if (sidecar !== expected) throw new Error(`${name} is not the canonical checksum for ${versionedName}`)
  }

  // A checksum can prove that a hosted tarball is immutable without proving
  // that it contains the source being released. Compare every package byte,
  // including package.json lifecycle scripts and dependency metadata, before a
  // site build may advertise this artifact.
  const entries = verifyDeterministicPackageArchive(versioned)
  for (const name of [
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'SBOM.cdx.json',
    'SECURITY.md',
    'THIRD_PARTY_NOTICES.md',
    'dist/cli.cjs',
    'package.json',
  ]) {
    const local = name === 'package.json' ? pkgBytes : await readFile(join(packageDir, name))
    const packed = entries.get(`package/${name}`)
    if (!packed || !local.equals(packed)) {
      throw new Error(`${versionedName} does not contain the current ${name}; bump the CLI version and run pnpm cli:release`)
    }
  }
  if (!entries.get('package/SBOM.cdx.json').equals(versionedSbom)) {
    throw new Error(`${versionedSbomName} does not describe the SBOM included in ${versionedName}`)
  }
  const packagedSbom = JSON.parse(versionedSbom.toString('utf8'))
  if (packagedSbom.metadata?.component?.name !== pkg.name || packagedSbom.metadata?.component?.version !== pkg.version) {
    throw new Error(`${versionedSbomName} does not identify ${pkg.name}@${pkg.version}`)
  }
  const expectedSerialNumber = cycloneDxSerialNumber(pkg.name, pkg.version)
  if (packagedSbom.bomFormat !== 'CycloneDX'
    || packagedSbom.specVersion !== '1.6'
    || packagedSbom.serialNumber !== expectedSerialNumber) {
    throw new Error(`${versionedSbomName} does not have the canonical CycloneDX identity ${expectedSerialNumber}`)
  }

  return { version: pkg.version, sha256: versionedSha }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : undefined
if (invokedPath === import.meta.url) {
  const result = await verifyRelease()
  process.stdout.write(`Verified immutable CodeTruss CLI ${result.version} release (${result.sha256})\n`)
}
