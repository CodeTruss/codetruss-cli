// Behaviour acceptance test for the SHIPPED CLI.
//
// Everything else in this package's `test` script checks packaging: the archive
// is reproducible, the verifier rejects tampering, the changelog forms a chain.
// None of it runs a rule. The public mirror carries no root `tests/` and no
// `packages/analyzer-engine/test/`, so the nine CI compatibility contexts and
// the tag-triggered release job could go green over a SAST behaviour regression
// — which is how the two findings below shipped and were caught by hand.
//
// This script closes that. It executes the built `dist/cli.cjs` over a committed
// fixture tree and asserts the findings the release must and must not produce.
// It lives under `packages/cli/`, so it reaches the mirror with the rest of the
// package and needs no hosted-app implementation to run.
//
// The expected verdicts are taken from the committed adjudication at
// `docs/benchmarks/cross-tool-2026-08/adjudication/verdicts.md`, sections
// "CodeTruss reported a parameterized query as CRITICAL SQL injection"
// (firecrawl `apps/api/src/db/rpc.ts:98`), "…and the same rule missed a real
// dynamic query" (uptime-kuma `server/monitor-types/postgres.js:35-63`), and
// sample #18 / "All three of CodeTruss's CRITICAL findings on the corpus are
// questionable" (excalidraw `.env.development:17` and `.env.production:17`, the
// publishable Firebase web `apiKey`). The benchmark repositories are NOT cloned
// here: minutes of network across nine contexts, and a release that depends on
// third-party repositories staying alive.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const workspaceRoot = resolve(packageDir, '../..')
const bundle = join(packageDir, 'dist', 'cli.cjs')
const fixtureRoot = join(scriptDir, 'fixtures', 'acceptance')
const FIXTURE_SUFFIX = '.fixture'

/**
 * What the shipped engine must say about each fixture.
 *
 * `line` is not written down: it is located in the fixture text by `anchor`, so
 * editing a fixture cannot silently retarget the assertion at a different
 * statement, and reformatting one does not produce a false failure.
 */
const EXPECTED = [
  {
    path: 'src/db/rpc.ts',
    ruleId: 'sql-injection',
    reported: false,
    why: 'drizzle `sql` tagged template — interpolations are bound parameters, not concatenation (fixed in 0.2.53)',
  },
  {
    path: 'src/monitor/postgres.js',
    ruleId: 'sql-injection',
    reported: true,
    anchor: 'client.query(query',
    severity: 'HIGH',
    cwe: 'CWE-89',
    messageIncludes: 'query',
    why: 'the whole query text is a function parameter on a database-shaped receiver (added in 0.2.53)',
  },
]

/**
 * What the shipped engine must say about each credential-shaped fixture line.
 *
 * The `secrets` analyzer is a registry pass, not the SAST pass, so these are
 * checked against `secrets` findings. Same anchor discipline as {@link EXPECTED}:
 * the line is located in the fixture text, never written down.
 *
 * These four are one truth table, not four independent cases, and the last row
 * is why the other three are safe. The publishable-client-identifier exemption
 * must never widen into "a Google API key is never a secret", so the same key
 * format, in the same committed `.env`, under a name the build tool does not
 * publish, is asserted to stay CRITICAL right beside them.
 */
const EXPECTED_SECRETS = [
  {
    path: '.env.production',
    anchor: 'VITE_APP_FIREBASE_CONFIG',
    severity: 'INFO',
    messageIncludes: 'public client identifier',
    publishableClientKey: true,
    why: 'a Firebase web config on one JSON line — public by design, was CRITICAL until 0.2.56',
  },
  {
    path: 'src/firebase.ts',
    anchor: 'apiKey:',
    severity: 'INFO',
    messageIncludes: 'public client identifier',
    publishableClientKey: true,
    why: 'the same config as an initializeApp({…}) argument, with no environment variable to read — was HIGH until 0.2.56',
  },
  {
    path: '.env.production',
    anchor: 'VITE_APP_GOOGLE_MAPS_KEY',
    severity: 'LOW',
    messageIncludes: 'inline the value into the client bundle',
    publishableClientKey: true,
    why: 'a publishable prefix with no Firebase config around it: public to every visitor, so a restriction question rather than a leak',
  },
  {
    path: '.env.production',
    anchor: 'MAPS_SERVER_KEY',
    severity: 'CRITICAL',
    messageIncludes: 'treated as compromised',
    publishableClientKey: false,
    why: 'the negative control: the same AIza format under a name the build tool does not publish is a committed credential and must keep firing',
  },
]

/**
 * Fixtures the local SAST parser reads. The rest of the tree exists for the
 * registry analyzers — a `.env` is not JavaScript — so `filesScanned` is
 * compared against this subset rather than the whole fixture count.
 */
const SAST_READABLE = /\.[cm]?[jt]sx?$/

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? packageDir,
    encoding: 'utf8',
    env: { ...process.env, ...options.env },
    windowsHide: true,
  })
  if (result.error) throw result.error
  const allowed = options.exitCodes ?? [0]
  if (!allowed.includes(result.status)) {
    throw new Error(`${command} ${args.join(' ')} exited with ${result.status}\n${result.stdout ?? ''}${result.stderr ?? ''}`)
  }
  // stdout only: a warning on stderr must not become part of a parsed report.
  return result.stdout ?? ''
}

/** Absolute paths of every file under `dir`, recursively. */
async function filesUnder(dir) {
  const entries = await readdir(dir, { withFileTypes: true, recursive: true })
  return entries.filter((e) => e.isFile()).map((e) => join(e.parentPath ?? e.path, e.name))
}

/**
 * Refuse to run against a bundle that is not this working tree's code.
 *
 * The point of this file is to test the artifact a user installs, so a stale
 * `dist/cli.cjs` — one built before the source edit under review, or left over
 * from another release — would report the old engine's verdicts and pass. That
 * is the same green-badge-means-nothing failure this script exists to close, so
 * it is checked rather than assumed. `pretest` rebuilds, so this only fires when
 * the script is run on its own after an edit.
 */
async function assertBundleIsCurrent(version) {
  const built = await stat(bundle).catch(() => {
    throw new Error(`${bundle} does not exist; run \`pnpm cli:build\` (a fresh worktree has no dist/)`)
  })
  const reported = run(process.execPath, [bundle, '--version']).trim()
  assert.equal(
    reported,
    `codetruss ${version}`,
    `dist/cli.cjs reports "${reported}" but package.json declares ${version}; the bundle is not this release`,
  )
  const sourceTrees = [join(packageDir, 'src'), join(workspaceRoot, 'packages', 'analyzer-engine', 'src')]
  for (const tree of sourceTrees) {
    for (const file of await filesUnder(tree)) {
      const source = await stat(file)
      if (source.mtimeMs > built.mtimeMs) {
        throw new Error(
          `${relative(workspaceRoot, file)} is newer than dist/cli.cjs; this would test a stale bundle. `
          + 'Run `pnpm cli:build` (or `pnpm --filter @codetruss/cli test`, whose pretest builds).',
        )
      }
    }
  }
  return sourceTrees.map((tree) => relative(workspaceRoot, tree))
}

/** Copy the fixture tree into `target`, stripping the `.fixture` suffix. */
async function materializeFixtures(target) {
  const sources = await filesUnder(fixtureRoot)
  assert.ok(sources.length > 0, `no fixtures found under ${fixtureRoot}`)
  const written = new Map()
  for (const source of sources) {
    assert.ok(
      source.endsWith(FIXTURE_SUFFIX),
      `${relative(fixtureRoot, source)} must end in ${FIXTURE_SUFFIX} so the repository's own lint and `
      + 'typecheck programs do not compile deliberately vulnerable code',
    )
    const logical = relative(fixtureRoot, source).slice(0, -FIXTURE_SUFFIX.length).split(sep).join('/')
    const text = await readFile(source, 'utf8')
    const destination = join(target, ...logical.split('/'))
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, text)
    written.set(logical, text)
  }
  return written
}

/** Run `review` then `report --json` in `repo`, and return the findings under test. */
function scan(repo, home, sastFixtureCount) {
  const env = {
    // Keep the run off the developer's (and the runner's) real config: the CLI
    // stores its signing key and verify-trust decisions under the user config
    // root, and this test must not create or consume either.
    CODETRUSS_SIGNING_KEY: join(home, 'signing-private.pem'),
    XDG_CONFIG_HOME: home,
  }
  const git = (...args) => run('git', ['-C', repo, ...args])
  git('init', '--quiet', '-b', 'main', '.')
  // The CLI reports the delta against a baseline commit. An empty baseline —
  // the policy file alone — makes the whole fixture tree the change, which is
  // the same construction `docs/benchmarks/cross-tool-2026-08/lib/run-codetruss.sh`
  // uses to scan a whole repository.
  run(process.execPath, [bundle, 'init', '--force', '--allow', '**'], { cwd: repo, env })
  git('add', '-f', '.codetruss.yml')
  git(
    '-c', 'user.email=acceptance@codetruss.local',
    '-c', 'user.name=CodeTruss Acceptance',
    '-c', 'commit.gpgsign=false',
    'commit', '--quiet', '-m', 'acceptance fixture baseline',
  )
  // PASS=0, REVIEW_REQUIRED=1 and FAILED=2 are all valid outcomes; the verdict
  // is not what is under test, the findings are. FAILED became reachable when
  // the fixtures gained a deliberately committed credential — the `.env`
  // negative control below is CRITICAL on purpose, and a tree containing one
  // SHOULD fail. Usage=3 and any crash still are not valid.
  run(process.execPath, [bundle, 'review', '--task', 'CLI acceptance fixture scan', '--no-verify'], {
    cwd: repo,
    env,
    exitCodes: [0, 1, 2],
  })
  const report = JSON.parse(run(process.execPath, [bundle, 'report', 'latest', '--json'], { cwd: repo, env }))
  const pass = report.analyzers?.passes?.find((p) => p.id === 'local-sast')
  assert.ok(pass, 'the receipt has no local-sast pass; the security analyzer did not run at all')
  assert.equal(pass.result.complete, true, 'the local-sast pass did not complete over a handful of small fixtures')
  assert.equal(pass.result.truncated, false, 'the local-sast pass truncated over a handful of small fixtures')
  assert.equal(
    pass.result.metrics?.filesScanned,
    sastFixtureCount,
    `local-sast scanned ${pass.result.metrics?.filesScanned} of ${sastFixtureCount} JS-family fixtures; every one must reach the engine`,
  )
  const secrets = report.analyzers?.passes?.find((p) => p.id === 'secrets')
  assert.ok(secrets, 'the receipt has no secrets pass; the credential analyzer did not run at all')
  assert.equal(secrets.result.complete, true, 'the secrets pass did not complete over a handful of small fixtures')
  return { sast: pass.result.findings, secrets: secrets.result.findings }
}

const version = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8')).version
const covered = await assertBundleIsCurrent(version)
const scratch = await mkdtemp(join(tmpdir(), 'codetruss-cli-acceptance-'))
const repo = join(scratch, 'repo')
const home = join(scratch, 'config')
await mkdir(repo, { recursive: true })
await mkdir(home, { recursive: true })

try {
  const fixtures = await materializeFixtures(repo)
  const sastFixtures = [...fixtures.keys()].filter((path) => SAST_READABLE.test(path))
  assert.ok(sastFixtures.length > 0, 'no JS-family fixture remains; the SAST expectations below could not fail')
  const findings = scan(repo, home, sastFixtures.length)
  const failures = []

  /** The line `anchor` sits on in `path`'s fixture text, 1-based. */
  const anchorLineIn = (path, anchor) => {
    const source = fixtures.get(path)
    assert.ok(source, `an expectation names ${path}, which no fixture produces`)
    const line = source.split('\n').findIndex((text) => text.includes(anchor)) + 1
    assert.ok(line > 0, `fixture ${path} no longer contains \`${anchor}\``)
    return line
  }

  for (const expectation of EXPECTED) {
    const source = fixtures.get(expectation.path)
    assert.ok(source, `EXPECTED names ${expectation.path}, which no fixture produces`)
    const matched = findings.sast.filter(
      (f) => f.filePath === expectation.path && f.metadata?.ruleId === expectation.ruleId,
    )
    const describe = (f) => `${f.severity} ${f.metadata?.ruleId} at ${f.filePath}:${f.line} — ${f.title}`

    if (!expectation.reported) {
      if (matched.length > 0) {
        failures.push(
          `${expectation.path}: expected NO ${expectation.ruleId} finding (${expectation.why}), got `
          + `${matched.length}:\n    ${matched.map(describe).join('\n    ')}`,
        )
      }
      continue
    }

    if (matched.length !== 1) {
      failures.push(
        `${expectation.path}: expected exactly 1 ${expectation.ruleId} finding (${expectation.why}), got `
        + `${matched.length}${matched.length ? `:\n    ${matched.map(describe).join('\n    ')}` : ''}`,
      )
      continue
    }
    const [finding] = matched
    const anchorLine = anchorLineIn(expectation.path, expectation.anchor)
    if (finding.line !== anchorLine) {
      failures.push(`${expectation.path}: ${expectation.ruleId} reported at line ${finding.line}, expected ${anchorLine} (\`${expectation.anchor}\`)`)
    }
    if (finding.severity !== expectation.severity) {
      failures.push(`${expectation.path}: ${expectation.ruleId} severity ${finding.severity}, expected ${expectation.severity}`)
    }
    if (finding.metadata?.cwe !== expectation.cwe) {
      failures.push(`${expectation.path}: ${expectation.ruleId} cwe ${finding.metadata?.cwe}, expected ${expectation.cwe}`)
    }
    if (!finding.description?.includes(expectation.messageIncludes)) {
      failures.push(`${expectation.path}: ${expectation.ruleId} message does not name \`${expectation.messageIncludes}\`: ${finding.description}`)
    }
  }

  for (const expectation of EXPECTED_SECRETS) {
    const anchorLine = anchorLineIn(expectation.path, expectation.anchor)
    const matched = findings.secrets.filter((f) => f.filePath === expectation.path && f.line === anchorLine)
    const describe = (f) => `${f.severity} at ${f.filePath}:${f.line} — ${f.title}`

    if (matched.length !== 1) {
      failures.push(
        `${expectation.path}:${anchorLine} (\`${expectation.anchor}\`): expected exactly 1 secrets finding `
        + `(${expectation.why}), got ${matched.length}${matched.length ? `:\n    ${matched.map(describe).join('\n    ')}` : ''}`,
      )
      continue
    }
    const [finding] = matched
    if (finding.severity !== expectation.severity) {
      failures.push(
        `${expectation.path}:${anchorLine} (\`${expectation.anchor}\`): secrets severity ${finding.severity}, `
        + `expected ${expectation.severity} — ${expectation.why}`,
      )
    }
    if (Boolean(finding.metadata?.publishableClientKey) !== expectation.publishableClientKey) {
      failures.push(
        `${expectation.path}:${anchorLine} (\`${expectation.anchor}\`): secrets metadata.publishableClientKey `
        + `${JSON.stringify(finding.metadata?.publishableClientKey)}, expected ${expectation.publishableClientKey}`,
      )
    }
    if (!finding.description?.includes(expectation.messageIncludes)) {
      failures.push(
        `${expectation.path}:${anchorLine} (\`${expectation.anchor}\`): secrets message does not say `
        + `\`${expectation.messageIncludes}\`: ${finding.description}`,
      )
    }
  }

  if (failures.length > 0) {
    throw new Error(
      `The shipped CLI ${version} does not behave as the benchmark adjudication requires:\n  - `
      + `${failures.join('\n  - ')}\n\n`
      + 'These fixtures reproduce findings recorded in docs/benchmarks/cross-tool-2026-08/adjudication/verdicts.md. '
      + 'Do not relax the assertion to make this pass.',
    )
  }

  process.stdout.write(
    `acceptance: dist/cli.cjs ${version} (newer than ${covered.join(' and ')}) reproduced `
    + `${EXPECTED.length + EXPECTED_SECRETS.length} adjudicated verdicts over ${fixtures.size} fixtures\n`,
  )
} finally {
  await rm(scratch, { recursive: true, force: true })
}
