// A release overwrote the previous release's heading once: CLI 0.2.36 replaced
// `## 0.2.35 — …` with its own heading, leaving 0.2.35's bullets orphaned under
// 0.2.36 and erasing 0.2.35 from the history entirely. Nothing caught it, because
// nothing read the changelog. These checks do.

const HEADING = /^## (?<version>\d+\.\d+\.\d+) — (?<date>\d{4}-\d{2}-\d{2})(?<suffix> \(unpublished\))?$/
const UNRELEASED = /^## Unreleased$/

function parseVersion(version) {
  const [major, minor, patch] = version.split('.').map(Number)
  return { major, minor, patch }
}

/**
 * True when `newer` is the immediate semver successor of `older`: the next patch
 * on the same minor, or the `.0` that opens the next minor or major. Anything
 * else is a gap (a lost entry) or a reordering.
 */
function succeeds(newer, older) {
  if (newer.major === older.major && newer.minor === older.minor) return newer.patch === older.patch + 1
  if (newer.major === older.major) return newer.minor === older.minor + 1 && newer.patch === 0
  return newer.major === older.major + 1 && newer.minor === 0 && newer.patch === 0
}

/**
 * Assert the changelog records `version` and that every release heading forms one
 * unbroken descending chain. `changelog` is the file's raw text.
 */
export function assertChangelogPolicy(changelog, version) {
  const lines = changelog.split('\n')
  const headings = []
  for (const [index, line] of lines.entries()) {
    const match = HEADING.exec(line)
    if (match) headings.push({ ...match.groups, line: index + 1, ...parseVersion(match.groups.version) })
  }
  if (headings.length === 0) throw new Error('CHANGELOG.md declares no release headings')

  // Nothing may sit between the preamble and the first release except an
  // optional, empty `## Unreleased`. Notes stranded above the newest release
  // heading are notes no released version claims.
  const firstHeadingIndex = headings[0].line - 1
  let sawUnreleased = false
  for (let index = 0; index < firstHeadingIndex; index += 1) {
    const line = lines[index]
    if (UNRELEASED.test(line)) {
      sawUnreleased = true
      continue
    }
    if (line.startsWith('## ')) {
      throw new Error(`CHANGELOG.md line ${index + 1}: unexpected section before the first release heading: ${line}`)
    }
    if (sawUnreleased && line.trim() !== '') {
      throw new Error(
        `CHANGELOG.md line ${index + 1}: "## Unreleased" still has content; move it into the release entry: ${line}`,
      )
    }
  }

  const seen = new Map()
  for (const heading of headings) {
    const previous = seen.get(heading.version)
    if (previous !== undefined) {
      throw new Error(`CHANGELOG.md declares version ${heading.version} twice (lines ${previous} and ${heading.line})`)
    }
    seen.set(heading.version, heading.line)
  }

  for (let index = 1; index < headings.length; index += 1) {
    const newer = headings[index - 1]
    const older = headings[index]
    if (!succeeds(newer, older)) {
      throw new Error(
        `CHANGELOG.md release chain breaks between ${newer.version} (line ${newer.line}) and ${older.version} `
        + `(line ${older.line}): every released version must appear exactly once, in descending order, with no gaps. `
        + 'A version that was never published still needs its own "(unpublished)" entry.',
      )
    }
  }

  if (!seen.has(version)) {
    throw new Error(
      `CHANGELOG.md has no "## ${version} — <date>" heading; the release being built must document itself. `
      + `Newest entry is ${headings[0].version}.`,
    )
  }
  if (seen.get(version) !== headings[0].line) {
    throw new Error(`CHANGELOG.md lists ${version} below a newer entry (${headings[0].version}); it must be the first release heading`)
  }
}
