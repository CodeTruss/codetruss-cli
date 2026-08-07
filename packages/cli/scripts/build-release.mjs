import { createHash } from 'node:crypto'
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { buildDeterministicPackageArchive } from './deterministic-package.mjs'
import { assertReleasePackagePolicy } from './release-package-policy.mjs'
import { verifyDeterministicPackageArchive } from './verify-deterministic-package.mjs'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const repoRoot = resolve(packageDir, '../..')
const downloadDir = join(repoRoot, 'public', 'downloads')
const scratch = await mkdtemp(join(tmpdir(), 'codetruss-cli-pack-'))

function run(command, args, cwd = packageDir) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} exited with ${result.status}`)
}

try {
  const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
  assertReleasePackagePolicy(pkg)
  // Invoke the build through Node directly. Package-manager shims are `.cmd`
  // files on Windows and cannot be spawned by Node without a shell; the build
  // itself is already a portable Node script and needs no shell mediation.
  run(process.execPath, [join(scriptDir, 'build.mjs')])
  const versionResult = spawnSync(process.execPath, [join(packageDir, 'dist', 'cli.cjs'), '--version'], {
    cwd: packageDir,
    encoding: 'utf8',
  })
  if (versionResult.status !== 0 || versionResult.stdout.trim() !== `codetruss ${pkg.version}`) {
    throw new Error(
      `CLI/package version mismatch: expected codetruss ${pkg.version}, received ${versionResult.stdout.trim() || versionResult.stderr.trim()}`,
    )
  }
  await mkdir(downloadDir, { recursive: true })
  const versionedName = `codetruss-cli-${pkg.version}.tgz`
  const latestName = 'codetruss-cli-latest.tgz'
  const versionedSbomName = `codetruss-cli-${pkg.version}.sbom.cdx.json`
  const latestSbomName = 'codetruss-cli-latest.sbom.cdx.json'
  const source = join(scratch, versionedName)
  const builtArchive = await buildDeterministicPackageArchive(packageDir, source)
  verifyDeterministicPackageArchive(builtArchive)
  const versioned = join(downloadDir, versionedName)
  const latest = join(downloadDir, latestName)
  const bytes = builtArchive
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  try {
    const publishedBytes = await readFile(versioned)
    const publishedSha256 = createHash('sha256').update(publishedBytes).digest('hex')
    if (publishedSha256 !== sha256) {
      throw new Error(
        `refusing to replace immutable ${versionedName}: existing ${publishedSha256}, new ${sha256}; bump the CLI version`,
      )
    }
  } catch (error) {
    if ((error).code === 'ENOENT') await copyFile(source, versioned)
    else throw error
  }
  await copyFile(versioned, latest)

  const sbomBytes = await readFile(join(packageDir, 'SBOM.cdx.json'))
  const sbomSha256 = createHash('sha256').update(sbomBytes).digest('hex')
  await writeFile(join(downloadDir, versionedSbomName), sbomBytes)
  await writeFile(join(downloadDir, latestSbomName), sbomBytes)

  await writeFile(`${versioned}.sha256`, `${sha256}  ${versionedName}\n`, 'utf8')
  await writeFile(`${latest}.sha256`, `${sha256}  ${latestName}\n`, 'utf8')
  await writeFile(
    join(downloadDir, 'codetruss-cli-latest.json'),
    `${JSON.stringify({
      name: pkg.name,
      version: pkg.version,
      url: `/downloads/${versionedName}`,
      latestUrl: `/downloads/${latestName}`,
      sha256,
      sbomUrl: `/downloads/${versionedSbomName}`,
      sbomSha256,
      node: pkg.engines.node,
      repository: 'https://github.com/DeliriumPulse/codetruss-cli',
      releaseUrl: `https://github.com/DeliriumPulse/codetruss-cli/releases/tag/v${pkg.version}`,
      attestationCommand: `gh attestation verify ${versionedName} --repo DeliriumPulse/codetruss-cli`,
    }, null, 2)}\n`,
    'utf8',
  )

  process.stdout.write(`CodeTruss CLI ${pkg.version}: public/downloads/${latestName} (${sha256})\n`)
} finally {
  await rm(scratch, { recursive: true, force: true })
}
