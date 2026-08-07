import {
  annotatedAnalyzerOutput,
  incompleteAnalyzerOutput,
  type Analyzer,
  type AnalyzerFinding,
  type RepoIndex,
} from './types'
import { classifyLines } from './comments'
import { CONVENTION_FILENAME } from './dead-code'

/**
 * Named value exports. Types are excluded: TypeScript consumes them
 * structurally and often invisibly, and excluding them halved the measured
 * unreferenced rate on every repository in the corpus.
 */
const EXPORT_DECLARATION =
  /^[ \t]*export\s+(?:(?:declare|async|abstract)\s+)*(?:function\s*\*|function|const|let|var|class|enum)\s+([A-Za-z_$][\w$]*)/gm

/** `export * from './x'` publishes every symbol in `x` without naming one. */
const BARREL_REEXPORT = /^[ \t]*export\s+\*(?:\s+as\s+[\w$]+)?\s+from\s+['"]([^'"]+)['"]/gm

const IDENTIFIER = /[A-Za-z_$][A-Za-z0-9_$]*/g

/**
 * Exports the framework loads by name. None of them is imported anywhere, and
 * every one would otherwise read as surface with no consumer.
 */
const CONVENTION_EXPORT = new Set([
  'metadata', 'generateMetadata', 'generateStaticParams', 'generateViewport',
  'loader', 'action', 'config', 'runtime', 'dynamic', 'dynamicParams',
  'revalidate', 'fetchCache', 'preferredRegion', 'maxDuration',
  'getServerSideProps', 'getStaticProps', 'getStaticPaths', 'middleware',
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
])

/**
 * ORM schema modules are consumed by codegen and migrations, not by imports.
 * One repository's Drizzle schema files alone drove its unreferenced-export
 * rate to 46.7%; without this gate the rule measures the ORM, not the code.
 */
const ORM_SCHEMA_PATH = /(?:^|\/)(?:db|database|drizzle|prisma)\/(?:.*\/)?[^/]*schema[^/]*$/i
const ORM_TABLE_CALL = /\b(?:pgTable|mysqlTable|sqliteTable|defineTable)\s*\(/
const ORM_RELATIONS = /^[ \t]*export\s+const\s+([A-Za-z_$][\w$]*)\s*=\s*relations\s*\(/gm

/** Runner entry points and route files: loaded by path, never by import. */
const RUNNER_PATH = /(?:^|\/)(?:scripts|bin|tools)\//
const PAGES_ROUTER_PATH = /^(?:src\/)?pages\//

/**
 * Convex deploys a whole functions directory and addresses its modules by path
 * at runtime: `internal.stripe.PREAUTH_getUserById` names a module and an
 * export, so the `export` keyword IS the registration and the only reference is
 * a string this pass cannot follow. Measured on a Convex starter, every one of
 * thirteen candidates in that directory would have been wrong.
 *
 * Detected from the toolchain, never from the directory name. Convex lets the
 * functions directory be renamed, its modules are commonly imported through a
 * path alias (`@cvx/_generated/server`) that no specifier match would catch,
 * and a directory called `convex` that no Convex toolchain ever touched is
 * ordinary code. Two independent structural signals are required: the
 * dependency in a manifest, and the `_generated/{api,server}` pair that
 * `convex dev` emits into the deployment root.
 *
 * Both are required deliberately. Over-gating on one weak signal would hide
 * real unused exports in any repository that happens to have a `_generated`
 * directory, and a missed gate costs one candidate finding rather than silence.
 */
const CONVEX_CODEGEN = /^(.*\/)?_generated\/(api|server)\.[^/]+$/

function convexDeploymentRoots(index: RepoIndex): string[] {
  if (!index.dependencies.has('convex')) return []
  const codegen = new Map<string, Set<string>>()
  for (const file of index.files) {
    const match = CONVEX_CODEGEN.exec(file.path)
    if (!match) continue
    const root = match[1] ?? ''
    const emitted = codegen.get(root) ?? new Set<string>()
    emitted.add(match[2])
    codegen.set(root, emitted)
  }
  // Only a directory holding BOTH halves of the codegen pair is a deployment root.
  return [...codegen].filter(([, emitted]) => emitted.size === 2).map(([root]) => root)
}

const JS_FILE = /\.(?:ts|tsx|js|jsx|mjs|cjs)$/

const CATCH_OPEN = /catch\s*\(\s*([A-Za-z_$][\w$]*)\s*(?::\s*[^)]*)?\)\s*\{$/
const CONSOLE_CALL = /^console\.\w+\([^{}]*\)\s*;?$/

interface SpeculativeFile {
  path: string
  names: string[]
}

interface RethrowFile {
  path: string
  lines: number[]
}

function directoryOf(path: string): string {
  const slash = path.lastIndexOf('/')
  return slash === -1 ? '' : path.slice(0, slash + 1)
}

/** Resolve a relative module specifier against the importing file's directory. */
function resolveSpecifier(fromPath: string, specifier: string): string | null {
  if (!specifier.startsWith('.')) return null
  const segments: string[] = []
  for (const part of `${directoryOf(fromPath)}${specifier}`.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') segments.pop()
    else segments.push(part)
  }
  return segments.join('/')
}

/** Paths whose symbols are re-exported wholesale by some barrel in the repo. */
function barrelPublishedPaths(index: RepoIndex): Set<string> {
  const targets = new Set<string>()
  for (const file of index.files) {
    if (!file.content || !JS_FILE.test(file.path)) continue
    for (const match of file.content.matchAll(BARREL_REEXPORT)) {
      const resolved = resolveSpecifier(file.path, match[1])
      if (resolved) targets.add(resolved)
    }
  }
  if (targets.size === 0) return targets
  const published = new Set<string>()
  for (const file of index.files) {
    const stem = file.path.replace(/\.[cm]?[jt]sx?$/, '')
    if (targets.has(stem) || targets.has(stem.replace(/\/index$/, ''))) published.add(file.path)
  }
  return published
}

/** Identifiers that occur in more than one indexed file. */
function crossFileIdentifiers(index: RepoIndex): Set<string> {
  const firstOwner = new Map<string, string>()
  const shared = new Set<string>()
  for (const file of index.files) {
    if (!file.content) continue
    const seen = new Set<string>()
    for (const match of file.content.matchAll(IDENTIFIER)) seen.add(match[0])
    for (const token of seen) {
      const owner = firstOwner.get(token)
      if (owner === undefined) firstOwner.set(token, file.path)
      else if (owner !== file.path) shared.add(token)
    }
  }
  return shared
}

/**
 * A `catch` whose whole body logs and rethrows. The nested-brace bail-out keeps
 * the shape unambiguous: a handler that builds an object or branches is doing
 * something, and this rule declines to guess what.
 */
function logAndRethrowLines(path: string, content: string): number[] {
  const lines = classifyLines(path, content)
  if (lines.length === 0) return []
  const hits: number[] = []
  for (let i = 0; i < lines.length; i++) {
    const open = lines[i].code.match(CATCH_OPEN)
    if (!open) continue
    const binding = open[1]
    const throwOnly = new RegExp(`^throw\\s+${binding}\\s*;?$`)
    let logs = 0
    let rethrows = 0
    for (let j = i + 1; j < lines.length; j++) {
      const code = lines[j].code
      if (code.length === 0) continue
      if (code === '}') {
        if (logs > 0 && rethrows === 1) hits.push(i + 1)
        break
      }
      if (code.includes('{') || code.includes('}')) break
      if (CONSOLE_CALL.test(code)) logs++
      else if (throwOnly.test(code)) rethrows++
      else break
    }
  }
  return hits
}

/**
 * Structure that exists for a consumer that does not.
 *
 * The disclosure in the description is load-bearing. The abstraction shapes
 * this rule set does NOT check — a single-implementation interface, an option
 * nobody overrides, a parameter never varied at any call site — each need the
 * cross-file symbol graph, and a receipt that stayed silent about them would
 * read as "no over-engineering found" when the pass structurally cannot see
 * them. Measured on real repositories, the regex versions of those shapes
 * returned between zero and three hits, most of them wrong.
 */
export const overengineeringAnalyzer: Analyzer = {
  id: 'overengineering',
  name: 'Speculative Structure',
  description:
    'Flags exported surface with no consumer and error handling that adds no behaviour. '
    + 'Abstraction-shape analysis (single-implementation interfaces, unused options, '
    + 'unvaried parameters) requires the hosted symbol graph and does not run locally.',
  async run(index) {
    const production = index.files.filter(
      (file) =>
        file.content
        && JS_FILE.test(file.path)
        && (file.kind === 'source' || file.kind === 'component' || file.kind === 'route'),
    )

    const candidateLimit = 1500
    const candidates = production.slice(0, candidateLimit)

    const rethrows: RethrowFile[] = []
    for (const file of candidates) {
      const lines = logAndRethrowLines(file.path, file.content!)
      if (lines.length > 0) rethrows.push({ path: file.path, lines })
    }

    // A library's exported surface IS its product. "Nothing in this repository
    // uses it" says nothing about a package whose consumers are elsewhere.
    const speculative: SpeculativeFile[] = []
    if (index.repoType !== 'library') {
      const generatedDirs = Object.keys(index.generatedFiles ?? {}).map((path) => directoryOf(path))
      const nearGenerated = (path: string) =>
        generatedDirs.some((dir) => (dir === '' ? !path.includes('/') : path.startsWith(dir)))
      const published = barrelPublishedPaths(index)
      const shared = crossFileIdentifiers(index)
      const convexRoots = convexDeploymentRoots(index)
      const convexDeployed = (path: string) =>
        convexRoots.some((root) => root === '' || path.startsWith(root))

      for (const file of candidates) {
        if (published.has(file.path)) continue
        if (nearGenerated(file.path) || RUNNER_PATH.test(file.path) || PAGES_ROUTER_PATH.test(file.path)) continue
        if (convexDeployed(file.path)) continue
        if (CONVENTION_FILENAME.test(file.path.split('/').pop()!)) continue
        const content = file.content!
        if (ORM_SCHEMA_PATH.test(file.path) || ORM_TABLE_CALL.test(content)) continue
        const relationNames = new Set([...content.matchAll(ORM_RELATIONS)].map((match) => match[1]))

        const names: string[] = []
        for (const match of content.matchAll(EXPORT_DECLARATION)) {
          const name = match[1]
          if (CONVENTION_EXPORT.has(name) || relationNames.has(name)) continue
          if (!shared.has(name)) names.push(name)
        }
        if (names.length > 0) speculative.push({ path: file.path, names: [...new Set(names)] })
      }
    }

    const findingLimit = 10
    // Every match is turned into a finding BEFORE the per-rule cap is applied.
    // The cap then splits them into what this pass reports and what it withholds
    // — a finding that only exists on one side of that split cannot be compared
    // against another run, and an uncomparable finding is one a delta calls
    // "introduced" the moment a cap slot frees up somewhere unrelated.
    const speculativeFindings: AnalyzerFinding[] = speculative.map((file) => {
      const listed = file.names.slice(0, 5).map((name) => `\`${name}\``).join(', ')
      const rest = file.names.length - Math.min(file.names.length, 5)
      return {
        category: 'DEAD_CODE',
        severity: 'INFO',
        title: `${file.names.length} export(s) with no consumer in ${file.path}`,
        description:
          `${listed}${rest > 0 ? ` and ${rest} more` : ''} ${file.names.length === 1 ? 'is' : 'are'} exported from `
          + `${file.path} and appear in no other indexed file, tests included. Exported surface with no consumer is an `
          + 'API for nobody: it has to be read, kept compiling, and refactored around. These are candidates — a symbol '
          + 'reached only through a dynamic import or a path built from strings looks the same to this pass.',
        filePath: file.path,
        suggestion: 'Drop the `export` keyword where the symbol is file-local, or delete it if nothing uses it.',
        impactScore: 15,
        effort: 'low',
        metadata: { exports: file.names.slice(0, 10) },
      }
    })

    const rethrowFindings: AnalyzerFinding[] = rethrows.map((file) => ({
      category: 'TECH_DEBT',
      severity: 'INFO',
      title: `${file.lines.length} catch block(s) log and rethrow in ${file.path}`,
      description:
        `${file.path} catches an error at line ${file.lines[0]}${file.lines.length > 1 ? ` and ${file.lines.length - 1} other place(s)` : ''}, `
        + 'logs it, and rethrows it unchanged. The handler adds a duplicate log line and no behaviour: the caller '
        + 'still receives the original error, and the stack is now reported twice.',
      filePath: file.path,
      line: file.lines[0],
      suggestion: 'Remove the catch and let the error propagate, or handle it where the extra context exists.',
      impactScore: 15,
      effort: 'low',
      metadata: { lines: file.lines.slice(0, 10) },
    }))

    const findings = [
      ...speculativeFindings.slice(0, findingLimit),
      ...rethrowFindings.slice(0, findingLimit),
    ]
    const withheld = [
      ...speculativeFindings.slice(findingLimit),
      ...rethrowFindings.slice(findingLimit),
    ]

    // Only the candidate-file cap loses coverage; the finding cap bounds output
    // over an analysis that still examined every candidate.
    const metrics = {
      candidates: production.length,
      candidateLimit,
      speculativeExportFiles: speculative.length,
      speculativeExports: speculative.reduce((total, file) => total + file.names.length, 0),
      logAndRethrowFiles: rethrows.length,
      abstractionShapeAnalysis: 'hosted-only',
    }
    if (production.length > candidateLimit) {
      return incompleteAnalyzerOutput(findings, {
        truncated: true,
        detail: `Speculative-structure analysis hit a candidate bound (${production.length} candidate files).`,
        metrics,
      }, withheld)
    }
    if (speculative.length > findingLimit || rethrows.length > findingLimit) {
      return annotatedAnalyzerOutput(findings, {
        detail: `Speculative-structure output capped at ${findingLimit} files per rule (${speculative.length} export, ${rethrows.length} rethrow).`,
        metrics,
      }, withheld)
    }
    return annotatedAnalyzerOutput(findings, { metrics })
  },
}
