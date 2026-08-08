import {
  annotatedAnalyzerOutput,
  incompleteAnalyzerOutput,
  measuredCoverage,
  type Analyzer,
  type AnalyzerFinding,
} from './types'

/**
 * Entry-point-ish files that are loaded by convention, not by import
 * (proxy.ts is Next 16's middleware — deleting it would drop the auth gate).
 * `instrumentation-client` / `instrumentation.edge` are the suffixed variants
 * Next.js and Sentry install; `*.stories.tsx` is collected by Storybook's glob.
 * Neither is ever imported.
 *
 * Shared so the speculative-export rule reads the same convention list rather
 * than deriving a second, drifting copy of it.
 */
export const CONVENTION_FILENAME = /(page|layout|route|loading|error|not-found|template|default|middleware|proxy|instrumentation|opengraph-image|twitter-image|icon|apple-icon|sitemap|robots|manifest|index|main|app|server|config|next-env|globals)\.[jt]sx?$|^instrumentation[-.][a-z]+\.[jt]sx?$|\.(stories|story)\.[jt]sx?$|\.(d|config|test|spec)\.[cm]?[jt]s$/

/**
 * The characters that end a filename stem in every reference shape the needle
 * below recognises: the three quote styles it looks between, plus whitespace
 * and the path separator.
 */
const STEM_BOUNDARY = /[\s/'"`]/

/** Module extensions the needle accepts after a stem. Mirrors `\.[cm]?[jt]sx?`. */
const REFERENCE_EXTENSION = /\.[cm]?[jt]sx?(?=[\s'"`])/g

/** `"…/stem"` — an extensionless import specifier closing on its quote. */
const QUOTED_PATH_TAIL = /\/([^\s/'"`]+)['"`]/g

function isQuote(char: string | undefined): boolean {
  return char === '"' || char === "'" || char === '`'
}

/**
 * Imported anywhere? look for `/stem'`, `/stem"`, or `from './stem`-style
 * refs — or a bare quoted `stem.ext` (a spawn-by-string worker path built
 * from segments, e.g. join(cwd, 'src', 'lib', 'batch-process.ts')).
 * The final alternative catches a path embedded in a longer command
 * string — `"sync-stripe": "node --env-file .env sync-stripe.js"` — where
 * the quote does not directly abut the path.
 */
function referenceNeedle(stem: string): RegExp {
  return new RegExp(
    `['"\`](?:[^'"\`]*/${escapeRegExp(stem)}(\\.[cm]?[jt]sx?)?|${escapeRegExp(stem)}\\.[cm]?[jt]sx?)['"\`]`
    + `|[\\s/]${escapeRegExp(stem)}\\.[cm]?[jt]sx?(?=[\\s'"\`])`,
  )
}

/**
 * Which of `stems` the concatenated corpus refers to, decided in TWO passes over
 * the corpus instead of one whole-corpus regex per candidate.
 *
 * Running `referenceNeedle` per candidate is O(candidates x corpus bytes): on a
 * 500k-LOC monorepo that is 1,500 sweeps of an 18 MB string, roughly 64 GB of
 * scanning, and it dominated the entire analysis. The membership question
 * answered here is deliberately the SAME one — matches inside strings, comments
 * and unrelated tokens included. This is a cost fix, not a precision change; a
 * stricter index would silently change which modules are called dead.
 *
 * The needle's three branches, rewritten as (character before stem, stem,
 * character after the stem's extension):
 *
 *   A. `['"`][^'"`]*\/stem['"`]`          — `/` before, quote after, NO extension
 *   B. `['"`]stem.ext['"`]`               — quote before, quote after
 *   C. `[\s/]stem.ext(?=[\s'"`])`         — whitespace or `/` before, whitespace
 *                                            or quote after
 *
 * B and C are found together by anchoring on the extension (rare in source text)
 * and reading backwards to the delimiter that opens the stem; the extension form
 * of A — `['"`][^'"`]*\/stem.ext['"`]` — is a strict subset of C, because C
 * already admits a `/` before and a quote after and asks for no opening quote.
 * A's extensionless form has no extension to anchor on, so it gets its own scan.
 *
 * Correct only for stems that contain no boundary character, which is why the
 * caller keeps the original needle for the ones that do.
 */
function referencedStems(corpus: string, stems: ReadonlySet<string>): Set<string> {
  const referenced = new Set<string>()
  if (stems.size === 0) return referenced
  const note = (stem: string) => {
    if (stems.has(stem)) referenced.add(stem)
  }

  // B and C. A stem with no boundary character is exactly the run of characters
  // between the extension and the delimiter that precedes it.
  for (const match of corpus.matchAll(REFERENCE_EXTENSION)) {
    const dot = match.index
    let start = dot
    while (start > 0 && !STEM_BOUNDARY.test(corpus[start - 1])) start -= 1
    // No opening delimiter at all, or nothing between it and the extension:
    // every branch needs one character of each.
    if (start === 0 || start === dot) continue
    // A quoted `"stem.ext"` (B) must close on its quote. The unquoted form (C)
    // may close on whitespace but can only OPEN on whitespace or `/`, so a
    // stem that opens on a quote and closes on whitespace matches neither.
    if (isQuote(corpus[start - 1]) && !isQuote(corpus[dot + match[0].length])) continue
    note(corpus.slice(start, dot))
  }

  // A, extensionless. `[^'"`]*` spans anything quote-free, so the opening quote
  // is satisfied by the nearest quote before the slash — that is, by any quote
  // occurring earlier in the corpus at all.
  const firstQuote = corpus.search(/['"`]/)
  if (firstQuote !== -1) {
    for (const match of corpus.matchAll(QUOTED_PATH_TAIL)) {
      if (match.index > firstQuote) note(match[1])
    }
  }
  return referenced
}

/**
 * Dead-code candidates: JS/TS modules that are never imported anywhere.
 * Heuristic (static string matching), so results are labeled candidates.
 */
export const deadCodeAnalyzer: Analyzer = {
  id: 'dead-code',
  name: 'Dead Code Candidates',
  description: 'Finds source modules that no other file appears to import.',
  async run(index) {
    const findings: AnalyzerFinding[] = []

    // Haystack: ALL indexed JS/TS files with content (routes, tests, configs
    // included) — imports from page.tsx/route.ts files must count as usage.
    const haystackFiles = index.files.filter(
      (f) => f.content && /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/.test(f.path),
    )
    // Candidates: only plain source/component modules can be "dead".
    const jsFiles = haystackFiles.filter(
      (f) => f.kind === 'source' || f.kind === 'component',
    )
    if (jsFiles.length < 5) return findings

    // package.json script values reference runner entrypoints ("npx tsx
    // lib/db/seed.ts") — raw manifest JSON satisfies the quoted-ref needle.
    const manifests = index.files.filter(
      (f) => f.content && /(^|\/)package\.json$/.test(f.path),
    )
    const allContent = haystackFiles
      .concat(manifests)
      .map((f) => f.content!)
      .join('\n')

    // Generated files are indexed with null content, so their imports are
    // invisible to the needle below. A generated OpenAPI client importing
    // `core/request.ts` would make that file look orphaned — excluding a file
    // must never manufacture dead code for the files it uses. Treat everything
    // under a directory that holds generated output as reachable.
    const generatedDirs = Object.keys(index.generatedFiles ?? {}).map((p) =>
      p.includes('/') ? p.slice(0, p.lastIndexOf('/') + 1) : '',
    )
    const nearGeneratedOutput = (path: string) =>
      generatedDirs.some((dir) => (dir === '' ? !path.includes('/') : path.startsWith(dir)))

    const candidateLimit = 1500
    // Select every candidate before testing any of them, so the reference index
    // is built once for exactly the stems that will be asked about. The order is
    // the order of `jsFiles`, which is the order the findings keep below.
    const candidates: Array<{ path: string; stem: string }> = []
    for (const file of jsFiles.slice(0, candidateLimit)) {
      if (nearGeneratedOutput(file.path)) continue
      // CLI/tooling entry points are invoked by runners, not imports
      if (/(^|\/)(scripts|bin|tools)\//.test(file.path)) continue
      // Next.js Pages Router: the PATH is the route, so nothing imports these.
      // Anchored at the project root so a `components/pages/` folder is unaffected.
      if (/^(src\/)?pages\//.test(file.path)) continue
      const base = file.path.split('/').pop()!
      if (CONVENTION_FILENAME.test(base)) continue
      // Tooling dotfiles (.prettierrc.js, .eslintrc.js) are loaded by name.
      if (base.startsWith('.')) continue
      const stem = base.replace(/\.[cm]?[jt]sx?$/, '')
      if (stem.length < 3) continue // too ambiguous to match safely
      candidates.push({ path: file.path, stem })
    }

    // A stem holding whitespace or a quote can straddle the delimiters the index
    // keys on, so those candidates keep the original whole-corpus needle. No
    // real filename does this; the fallback exists so the rewrite cannot narrow
    // the rule by accident on one that does.
    const indexable = new Set(
      candidates.map((c) => c.stem).filter((stem) => !STEM_BOUNDARY.test(stem)),
    )
    const referenced = referencedStems(allContent, indexable)
    const isReferenced = (stem: string) =>
      indexable.has(stem) ? referenced.has(stem) : referenceNeedle(stem).test(allContent)

    for (const { path, stem } of candidates) {
      if (isReferenced(stem)) continue
      findings.push({
        category: 'DEAD_CODE',
        severity: 'LOW',
        title: `Possibly unused module: ${path}`,
        description: `No other file appears to import "${stem}". If it is not loaded by convention or tooling, it is dead code.`,
        filePath: path,
        suggestion: 'Verify with your bundler or `knip`/`ts-prune`, then delete if truly unused.',
        impactScore: 35,
        effort: 'low',
      })
    }
    const findingLimit = 20
    // Only the candidate-file cap is real coverage loss; the finding cap just
    // bounds OUTPUT over an analysis that covered every candidate file.
    const truncated = jsFiles.length > candidateLimit
    const output = findings.slice(0, findingLimit)
    // Unreported, but retained as evidence that this tree already contained
    // them — a baseline/final comparison must not read a finding surfacing into
    // a freed cap slot as one the change introduced.
    const withheld = findings.slice(findingLimit)
    if (truncated) {
      return incompleteAnalyzerOutput(output, {
        truncated: true,
        // The candidate list was built from the whole tree before the slice, so
        // the files the bound cut are counted, not merely unknown.
        coverageRatio: measuredCoverage(candidateLimit, jsFiles.length),
        detail: `Dead-code analysis examined ${candidateLimit} of ${jsFiles.length} candidate files (${findings.length} matches).`,
        metrics: { candidates: jsFiles.length, candidateLimit, matches: findings.length, findingLimit },
      }, withheld)
    }
    if (findings.length > findingLimit) {
      return annotatedAnalyzerOutput(output, {
        detail: `Dead-code output capped at ${findingLimit} of ${findings.length} matches.`,
        metrics: { candidates: jsFiles.length, candidateLimit, matches: findings.length, findingLimit },
      }, withheld)
    }
    return output
  },
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
