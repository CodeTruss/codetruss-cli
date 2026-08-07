import type { InferredScopeRoot, ScopeClassification } from './types.js'

/**
 * Turn-scoped scope inference.
 *
 * Scope drift is the one detection CodeTruss has that nobody else runs, and on
 * a stranger's first session it fires the moment an agent touches something
 * reasonable outside whatever directories `setup` happened to find on disk.
 * A signature detection that debuts as a false alarm is how a real signal gets
 * ignored.
 *
 * The fix is not a looser policy. It is a second, weaker kind of in-scope: an
 * allowance supported by THIS turn's own evidence, recorded on the receipt as
 * inferred so a reviewer can always tell it apart from scope the repository
 * actually approved.
 *
 * Every rule below is a pure function of the task text, the turn's changed
 * files, and the configured globs. Nothing reads the filesystem and nothing is
 * carried between turns, so a reader holding only the signed receipt can
 * recompute the same allowances and check them.
 */

/** More roots than this is not an inference, it is a repository-wide allow. */
const MAX_INFERRED_ROOTS = 8

/**
 * Directory names that carry no feature meaning. "add a test" must not name
 * `test/` as the subject of the task.
 */
const GENERIC_DIRECTORY_NAMES = new Set([
  'app', 'apps', 'build', 'client', 'common', 'components', 'config', 'core', 'dist', 'docs',
  'e2e', 'internal', 'lib', 'libs', 'node_modules', 'package', 'packages', 'public', 'scripts',
  'server', 'shared', 'source', 'spec', 'specs', 'src', 'test', 'tests', 'types', 'util', 'utils',
  '__tests__',
])

const TEST_DIRECTORY_NAMES = new Set(['test', 'tests', '__tests__', 'spec', 'specs', 'e2e'])

/** A slash-bearing token in prose: `src/auth`, `packages/cli/src/git.ts`. */
const TASK_PATH_TOKEN = /[A-Za-z0-9_@.-]+(?:\/[A-Za-z0-9_@.-]+)+/g

const GLOB_MAGIC = /[*?[\]{}!+@(]/

/**
 * The structural minimum inference needs from a changed file. `ChangedFile`
 * satisfies it, and so does the mid-turn hook's cheaper per-tool-call view.
 */
export interface ScopeCandidate {
  path: string
  oldPath?: string
  classification: ScopeClassification
  sensitive?: string
  dependency: boolean
}

export interface TurnScopeInput {
  /** The turn's task text. Empty when the caller has no authenticated task. */
  task: string
  files: ScopeCandidate[]
  allow: string[]
  deny: string[]
}

function normalizePath(path: string): string {
  return path.replaceAll('\\', '/').replace(/^\.\//, '')
}

/** The immediate parent, or '' for a file sitting at the repository root. */
function parentDirectory(path: string): string {
  const normalized = normalizePath(path)
  const separator = normalized.lastIndexOf('/')
  return separator <= 0 ? '' : normalized.slice(0, separator)
}

function covers(root: string, path: string): boolean {
  const normalized = normalizePath(path)
  return normalized === root || normalized.startsWith(`${root}/`)
}

/**
 * Inference may only ever reach a path that is currently outside scope, is not
 * a secrets or config surface, and is not a dependency manifest. Denied paths
 * never reach here at all: deny is resolved before inference runs and is the
 * one classification inference cannot change.
 */
function inferable(file: ScopeCandidate): boolean {
  return file.classification === 'unexpected' && !file.sensitive && !file.dependency
}

function words(value: string): string[] {
  return value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)
}

function containsWordSequence(haystack: string[], needle: string[]): boolean {
  if (needle.length === 0 || needle.length > haystack.length) return false
  for (let start = 0; start + needle.length <= haystack.length; start += 1) {
    if (needle.every((word, offset) => haystack[start + offset] === word)) return true
  }
  return false
}

/** Every ancestor directory of a path, repository root excluded. */
function ancestorDirectories(path: string): string[] {
  const parts = normalizePath(path).split('/').filter(Boolean)
  const directories: string[] = []
  for (let depth = 1; depth < parts.length; depth += 1) directories.push(parts.slice(0, depth).join('/'))
  return directories
}

function isTestPath(path: string): boolean {
  const parts = normalizePath(path).split('/')
  const name = (parts.at(-1) ?? '').toLowerCase()
  return parts.slice(0, -1).some((part) => TEST_DIRECTORY_NAMES.has(part.toLowerCase()))
    || /\.(test|spec)\.[a-z0-9]+$/.test(name)
    || /_test\.[a-z0-9]+$/.test(name)
    || name.startsWith('test_')
}

/** `reset.test.ts`, `reset_test.go`, and `test_reset.py` all stem to `reset`. */
function fileStem(path: string): string {
  return (normalizePath(path).split('/').at(-1) ?? '')
    .toLowerCase()
    .replace(/\.[a-z0-9]+$/, '')
    .replace(/\.(test|spec)$/, '')
    .replace(/_test$/, '')
    .replace(/^test_/, '')
}

/** The literal directory prefix an allow glob commits to: `src/auth/**` → `src/auth`. */
function globPrefix(glob: string): string {
  const literal: string[] = []
  for (const part of normalizePath(glob.trim()).split('/')) {
    if (GLOB_MAGIC.test(part)) break
    literal.push(part)
  }
  return literal.join('/').replace(/\/+$/, '')
}

/**
 * An explicit allow root is a decision, not a default. If the repository
 * approved `src/auth/**`, an inferred `src` would quietly replace that
 * narrowing with its parent, so any inferred root that is an ancestor of — or
 * equal to — an approved root is discarded. Inference may name a sibling this
 * turn worked in; it may never climb above a line the user drew.
 */
function widensExplicitScope(root: string, explicitPrefixes: string[]): boolean {
  return explicitPrefixes.some((prefix) => prefix === root || prefix.startsWith(`${root}/`))
}

function taskPathTokens(task: string): string[] {
  const tokens: string[] = []
  for (const raw of task.match(TASK_PATH_TOKEN) ?? []) {
    const token = normalizePath(raw).replace(/\/+$/, '')
    if (!token || token.startsWith('/') || /^[a-z]:/i.test(token)) continue
    if (token.split('/').some((part) => part === '..' || part === '.')) continue
    if (!tokens.includes(token)) tokens.push(token)
  }
  return tokens
}

/**
 * Derive this turn's inferred allowances, in trust order:
 *
 * 1. `task-reference` — the task names a path, or names a directory by its own
 *    feature name, that the turn actually changed files under.
 * 2. `working-set` — changed files cluster under one shared parent directory.
 *    The parent is the file's immediate directory, never a climb toward the
 *    repository root, and never the repository root itself. With approved allow
 *    roots present a cluster needs two files; with none configured a single
 *    file establishes its directory, because there is no approved scope for it
 *    to drift from and the receipt says the scope was inferred entirely.
 * 3. `sibling-test` — a test file whose name mirrors a source file already in
 *    scope. Only that exact file is admitted, never its directory.
 */
export function inferTurnScope(input: TurnScopeInput): InferredScopeRoot[] {
  const candidates = input.files.filter(inferable)
  if (candidates.length === 0) return []
  const explicitPrefixes = input.allow.map(globPrefix).filter(Boolean)
  const paths = [...new Set(candidates.map((file) => normalizePath(file.path)))].sort()
  const roots: InferredScopeRoot[] = []
  const covered = (path: string) => roots.some((root) => covers(root.root, path))
  const admit = (root: InferredScopeRoot): void => {
    if (roots.length >= MAX_INFERRED_ROOTS) return
    if (!root.root || root.root === '.') return
    if (roots.some((existing) => existing.root === root.root)) return
    if (widensExplicitScope(root.root, explicitPrefixes)) return
    if (!paths.some((path) => covers(root.root, path) && !covered(path))) return
    roots.push(root)
  }

  for (const token of taskPathTokens(input.task)) {
    admit({ root: token, basis: 'task-reference', evidence: [token] })
  }

  const taskWords = words(input.task)
  for (const path of paths) {
    for (const directory of ancestorDirectories(path)) {
      const name = directory.split('/').at(-1) ?? ''
      if (GENERIC_DIRECTORY_NAMES.has(name.toLowerCase())) continue
      const nameWords = words(name)
      if (!nameWords.some((word) => word.length >= 3)) continue
      if (!containsWordSequence(taskWords, nameWords)) continue
      admit({ root: directory, basis: 'task-reference', evidence: [nameWords.join(' ')] })
    }
  }

  const cohesion = explicitPrefixes.length === 0 ? 1 : 2
  const groups = new Map<string, string[]>()
  for (const path of paths) {
    if (covered(path)) continue
    const parent = parentDirectory(path)
    if (!parent) continue
    groups.set(parent, [...(groups.get(parent) ?? []), path])
  }
  const ordered = [...groups].sort(([leftRoot, left], [rightRoot, right]) => (
    right.length - left.length || leftRoot.localeCompare(rightRoot)
  ))
  for (const [parent, members] of ordered) {
    if (members.length < cohesion) continue
    admit({ root: parent, basis: 'working-set', evidence: members })
  }

  const sourceStems = new Map<string, string>()
  for (const file of input.files) {
    const path = normalizePath(file.path)
    if (isTestPath(path) || file.classification === 'denied' || file.sensitive) continue
    if (file.classification === 'allowed' || covered(path)) sourceStems.set(fileStem(path), path)
  }
  for (const path of paths) {
    if (covered(path) || !isTestPath(path)) continue
    const source = sourceStems.get(fileStem(path))
    if (!source) continue
    admit({ root: path, basis: 'sibling-test', evidence: [source] })
  }

  return roots
}

/**
 * Apply inferred allowances and report only the roots that actually covered a
 * file, so the receipt never advertises an allowance that did nothing.
 */
export function applyInferredScope<T extends ScopeCandidate>(
  files: T[],
  roots: InferredScopeRoot[],
): { files: T[]; roots: InferredScopeRoot[] } {
  if (roots.length === 0) return { files, roots }
  const used = new Set<string>()
  const applied = files.map((file) => {
    if (!inferable(file)) return file
    // A rename is in scope only when its destination AND its origin are: the
    // origin is exactly where drift hides behind a plausible-looking new path.
    const touched = [file.path, ...(file.oldPath ? [file.oldPath] : [])]
    const matched = roots.filter((root) => touched.every((path) => covers(root.root, path)))
    if (matched.length === 0) return file
    for (const root of matched) used.add(root.root)
    return { ...file, classification: 'inferred' as const }
  })
  return { files: applied, roots: roots.filter((root) => used.has(root.root)) }
}
