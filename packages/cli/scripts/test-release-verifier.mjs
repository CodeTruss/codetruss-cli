import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildDeterministicPackageArchive, PACKAGE_ARCHIVE_FILES } from './deterministic-package.mjs'
import { attestationCommand, buildReleaseManifest, serialiseReleaseManifest } from './release-metadata.mjs'
import { verifyRelease } from './verify-release.mjs'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const scratch = await mkdtemp(join(tmpdir(), 'codetruss-release-verifier-'))
const downloadDir = join(scratch, 'downloads')
const tamperedPackageDir = join(scratch, 'tampered-package')
const digest = (value) => createHash('sha256').update(value).digest('hex')

async function writeRelease(archivePackageDir = packageDir) {
  const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
  const versionedName = `codetruss-cli-${pkg.version}.tgz`
  const latestName = 'codetruss-cli-latest.tgz'
  const versionedSbomName = `codetruss-cli-${pkg.version}.sbom.cdx.json`
  const archive = await buildDeterministicPackageArchive(archivePackageDir, join(downloadDir, versionedName))
  const sha256 = digest(archive)
  const sbom = await readFile(join(archivePackageDir, 'SBOM.cdx.json'))
  const sbomSha256 = digest(sbom)
  await writeFile(join(downloadDir, latestName), archive)
  await writeFile(join(downloadDir, versionedSbomName), sbom)
  await writeFile(join(downloadDir, 'codetruss-cli-latest.sbom.cdx.json'), sbom)
  await writeFile(join(downloadDir, `${versionedName}.sha256`), `${sha256}  ${versionedName}\n`)
  await writeFile(join(downloadDir, `${latestName}.sha256`), `${sha256}  ${latestName}\n`)
  await writeFile(
    join(downloadDir, 'codetruss-cli-latest.json'),
    serialiseReleaseManifest(buildReleaseManifest({ pkg, sha256, sbomSha256 })),
  )
  return { versionedName, latestName }
}

try {
  // The published manifest is a copy-paste instruction. A command that names a
  // repository GitHub cannot resolve is worse than no command at all, so pin the
  // exact string. Every release still in circulation is attested under the
  // organisation, so the command does not vary by version — the assertions below
  // are what would fail if a version-dependent form were reintroduced.
  assert.equal(
    attestationCommand('codetruss-cli-0.2.41.tgz'),
    'gh attestation verify codetruss-cli-0.2.41.tgz --repo CodeTruss/codetruss-cli',
  )
  for (const version of ['0.2.14', '0.2.36', '0.2.39', '0.2.40', '0.2.41', '0.3.0', '1.0.0']) {
    const command = attestationCommand(`codetruss-cli-${version}.tgz`)
    assert.equal(
      command,
      `gh attestation verify codetruss-cli-${version}.tgz --repo CodeTruss/codetruss-cli`,
      `${version} must advertise the organisation-scoped command, which is what verifies today`,
    )
    assert.doesNotMatch(
      command,
      /--repo DeliriumPulse\//,
      `${version} must not advertise the transferred repository slug, which returns HTTP 404`,
    )
  }

  // The live pointer file is served to users between releases, so it must stay
  // in step with the generator without waiting for the next artifact build.
  const shippedManifest = JSON.parse(
    await readFile(join(resolve(packageDir, '../..'), 'public', 'downloads', 'codetruss-cli-latest.json'), 'utf8'),
  )
  assert.equal(
    shippedManifest.attestationCommand,
    attestationCommand(`codetruss-cli-${shippedManifest.version}.tgz`),
    'public/downloads/codetruss-cli-latest.json advertises a stale attestation command',
  )
  assert.equal(shippedManifest.repository, 'https://github.com/CodeTruss/codetruss-cli')
  assert.equal(
    shippedManifest.releaseUrl,
    `https://github.com/CodeTruss/codetruss-cli/releases/tag/v${shippedManifest.version}`,
  )

  await mkdir(downloadDir, { recursive: true })
  const names = await writeRelease()
  await verifyRelease({ packageDir, downloadDir })

  for (const file of PACKAGE_ARCHIVE_FILES) {
    const target = join(tamperedPackageDir, file.source)
    await mkdir(dirname(target), { recursive: true })
    await copyFile(join(packageDir, file.source), target)
  }
  const maliciousManifest = JSON.parse(await readFile(join(tamperedPackageDir, 'package.json'), 'utf8'))
  maliciousManifest.scripts = { ...maliciousManifest.scripts, postinstall: 'node -e "process.exit(99)"' }
  await writeFile(join(tamperedPackageDir, 'package.json'), `${JSON.stringify(maliciousManifest, null, 2)}\n`)
  await writeRelease(tamperedPackageDir)
  await assert.rejects(() => verifyRelease({ packageDir, downloadDir }), /current package\.json/)
  await assert.rejects(
    () => verifyRelease({ packageDir: tamperedPackageDir, downloadDir }),
    /postinstall install lifecycle script/,
  )

  delete maliciousManifest.scripts.postinstall
  maliciousManifest.dependencies = { 'runtime-surprise': '1.0.0' }
  await writeFile(join(tamperedPackageDir, 'package.json'), `${JSON.stringify(maliciousManifest, null, 2)}\n`)
  await writeRelease(tamperedPackageDir)
  await assert.rejects(
    () => verifyRelease({ packageDir: tamperedPackageDir, downloadDir }),
    /must not declare dependencies/,
  )

  delete maliciousManifest.dependencies
  for (const [field, value] of [
    ['registry', 'https://packages.example.invalid'],
    ['tag', 'preview'],
  ]) {
    maliciousManifest.publishConfig = { access: 'public', [field]: value }
    await writeFile(join(tamperedPackageDir, 'package.json'), `${JSON.stringify(maliciousManifest, null, 2)}\n`)
    await writeRelease(tamperedPackageDir)
    await assert.rejects(
      () => verifyRelease({ packageDir: tamperedPackageDir, downloadDir }),
      /package access or supported Node policy is invalid/,
    )
  }

  await writeRelease()
  const metadataPath = join(downloadDir, 'codetruss-cli-latest.json')
  const metadata = JSON.parse(await readFile(metadataPath, 'utf8'))
  await writeFile(metadataPath, `${JSON.stringify({ ...metadata, unexpected: true }, null, 2)}\n`)
  await assert.rejects(() => verifyRelease({ packageDir, downloadDir }), /metadata is not the canonical manifest/)

  await writeRelease()
  const latestSidecar = join(downloadDir, `${names.latestName}.sha256`)
  await writeFile(latestSidecar, `${await readFile(latestSidecar, 'utf8')}untrusted trailing bytes\n`)
  await assert.rejects(() => verifyRelease({ packageDir, downloadDir }), /not the canonical checksum/)

  for (const file of PACKAGE_ARCHIVE_FILES) {
    await copyFile(join(packageDir, file.source), join(tamperedPackageDir, file.source))
  }
  const noncanonicalSbom = JSON.parse(await readFile(join(tamperedPackageDir, 'SBOM.cdx.json'), 'utf8'))
  delete noncanonicalSbom.serialNumber
  await writeFile(join(tamperedPackageDir, 'SBOM.cdx.json'), `${JSON.stringify(noncanonicalSbom, null, 2)}\n`)
  await writeRelease(tamperedPackageDir)
  await assert.rejects(
    () => verifyRelease({ packageDir: tamperedPackageDir, downloadDir }),
    /does not have the canonical CycloneDX identity/,
  )
} finally {
  await rm(scratch, { recursive: true, force: true })
}

process.stdout.write('Release integrity verifier tests passed.\n')
