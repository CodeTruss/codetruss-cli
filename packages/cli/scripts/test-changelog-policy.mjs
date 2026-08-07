import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertChangelogPolicy } from './changelog-policy.mjs'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const preamble = [
  '# Changelog',
  '',
  'CodeTruss CLI follows semantic versioning.',
  '',
  '## Unreleased',
  '',
].join('\n')

const changelog = (...entries) => `${preamble}${entries.map((entry) => `${entry}\n`).join('\n')}`
const entry = (version, date = '2026-08-07', body = '- a change') => `## ${version} — ${date}\n\n${body}`

// The shipped changelog and the version it documents must satisfy the policy.
const shipped = await readFile(join(packageDir, 'CHANGELOG.md'), 'utf8')
const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'))
assertChangelogPolicy(shipped, pkg.version)

// A well-formed chain passes, including the roll from one minor to the next.
assertChangelogPolicy(changelog(entry('0.2.1'), entry('0.2.0'), entry('0.1.1')), '0.2.1')
assertChangelogPolicy(changelog(entry('1.0.0'), entry('0.9.3'), entry('0.9.2')), '1.0.0')
// "(unpublished)" entries still count as links in the chain.
assertChangelogPolicy(
  changelog(entry('0.2.2'), `## 0.2.1 — 2026-08-06 (unpublished)\n\n- skipped`, entry('0.2.0')),
  '0.2.2',
)

// (a) The version being released must have its own heading.
assert.throws(
  () => assertChangelogPolicy(changelog(entry('0.2.1'), entry('0.2.0')), '0.2.2'),
  /no "## 0\.2\.2 — <date>" heading/,
)

// (b) The exact 0.2.36 regression: a release overwrites the previous heading,
// leaving a gap where 0.2.35 used to be.
assert.throws(
  () => assertChangelogPolicy(changelog(entry('0.2.36'), entry('0.2.34'), entry('0.2.33')), '0.2.36'),
  /release chain breaks between 0\.2\.36 .* and 0\.2\.34/,
)

// (b) A version listed twice.
assert.throws(
  () => assertChangelogPolicy(changelog(entry('0.2.2'), entry('0.2.2'), entry('0.2.1')), '0.2.2'),
  /declares version 0\.2\.2 twice/,
)

// (b) Headings out of descending order.
assert.throws(
  () => assertChangelogPolicy(changelog(entry('0.2.0'), entry('0.2.1'), entry('0.1.1')), '0.2.0'),
  /release chain breaks between 0\.2\.0 .* and 0\.2\.1/,
)

// (b) The released version must be the newest entry, not buried mid-file.
assert.throws(
  () => assertChangelogPolicy(changelog(entry('0.2.2'), entry('0.2.1'), entry('0.2.0')), '0.2.1'),
  /lists 0\.2\.1 below a newer entry/,
)

// (b) Notes stranded above the newest release heading belong to no version.
assert.throws(
  () => assertChangelogPolicy(
    `${preamble}- an orphaned bullet\n\n${entry('0.2.1')}\n\n${entry('0.2.0')}\n`,
    '0.2.1',
  ),
  /"## Unreleased" still has content/,
)

// (b) A non-release section wedged above the first release heading.
assert.throws(
  () => assertChangelogPolicy(
    `# Changelog\n\n## Notes\n\n${entry('0.2.1')}\n\n${entry('0.2.0')}\n`,
    '0.2.1',
  ),
  /unexpected section before the first release heading/,
)

// A changelog with no releases at all is not a changelog.
assert.throws(() => assertChangelogPolicy(preamble, '0.2.1'), /declares no release headings/)

process.stdout.write('changelog policy: chain, uniqueness, ordering, and self-documentation enforced\n')
