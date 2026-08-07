import { createRequire } from 'node:module'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { compileFunction } from 'node:vm'
import type { ParsedTree, SastLanguage, SastParser, SyntaxNode } from '@codetruss/analyzer-engine/security/lang'
import { MAX_SOURCE_BYTES } from '@codetruss/analyzer-engine/security/lang'
import { inspectGrammarPack, type GrammarPackState } from './grammar-pack.js'
import type { PinnedGrammarFile, PinnedGrammarPack } from './grammar-pack-manifest.js'

/**
 * Turn a verified grammar pack into the {@link SastParser} the engine expects.
 *
 * This is the same `web-tree-sitter` runtime, the same compiled grammar and the
 * same load sequence the hosted audit uses — deliberately, because that identity
 * is the whole claim: with a pack installed, Python is not analyzed by a local
 * approximation of the hosted pass, it is analyzed by the hosted pass's own
 * machinery. The only difference is where the bytes were resolved from.
 *
 * Nothing here reads the pack from disk. {@link inspectGrammarPack} performs the
 * single read of each artifact and hands back the buffers it hashed; this module
 * executes those buffers and nothing else. That is the point: a loader that
 * hashes a path and then re-opens it to execute it has verified one file and run
 * another, and the gap between the two reads is long enough — three digests and
 * a `readdir` — for a `rename(2)` loop to land a hostile module in it. There is
 * no path here for such a swap to reach, because there is no second read.
 */

/** The subset of the web-tree-sitter 0.22.x surface this loader drives. */
interface TreeSitterLanguage { readonly __brand?: never }
interface TreeSitterTree {
  rootNode: SyntaxNode & { hasError: boolean }
  delete(): void
}
interface TreeSitterParser {
  setLanguage(language: TreeSitterLanguage): void
  parse(content: string): TreeSitterTree | null
}
interface TreeSitterModule {
  new(): TreeSitterParser
  init(moduleOptions?: { wasmBinary?: Uint8Array; locateFile?: () => string }): Promise<void>
  Language: { load(input: string | Uint8Array): Promise<TreeSitterLanguage> }
}

export type GrammarParserLoad =
  | { status: 'verified'; parser: SastParser; languages: ReadonlySet<SastLanguage> }
  | { status: 'absent' }
  /**
   * Why the pack is unusable, kept apart from WHAT went wrong.
   *
   * `digest` means the pack on disk is not what this CLI published. `runtime`
   * means it is exactly what this CLI published and emscripten still could not
   * start — an OOM, a Node build without the WASM features the runtime needs, a
   * `MAP_FAILED` under memory pressure. Collapsing the two lets a receipt accuse
   * a user's install of tampering because their machine ran out of memory, which
   * is both false and unfalsifiable from the reader's side.
   */
  | { status: 'failed'; kind: 'digest' | 'runtime'; reason: string }

/**
 * One tree-sitter runtime per pack directory, per process.
 *
 * This cache is CORRECTNESS, not an optimization. `web-tree-sitter`'s emscripten
 * glue reassigns `module.exports = Module` from its Node branch once the runtime
 * initializes, which overwrites its own entry in Node's require cache. A second
 * `require()` of the same file therefore hands back the emscripten Module object
 * instead of the Parser class, and `Parser.init` is suddenly not a function.
 *
 * A single review loads the pack TWICE — once for the baseline tree and once for
 * the final tree — so without this the second analysis of every run would fail
 * to load the grammar and silently report Python as unanalyzable. Requiring the
 * runtime exactly once per process also matches the hosted loader, which reuses
 * one Parser instance because a fresh one never returns its WASM working memory.
 *
 * Reusing the parser across loads is sound only because the digests are pinned
 * CONSTANTS: any two runs that reach `verified` did so over byte-identical
 * artifacts, so the cached parser cannot be older than what was just verified in
 * any way that matters. Verification itself is deliberately NOT cached —
 * {@link loadGrammarParser} re-inspects on every call.
 */
const runtimeCache = new Map<string, Promise<{ parser: SastParser } | { reason: string }>>()

/**
 * Load a pack's parser, or explain why it is unavailable.
 *
 * Never throws for an unavailable pack. Absence and tampering are COVERAGE
 * answers, not errors: the caller turns them into a disclosure that Python was
 * skipped and why, which is the only honest outcome. Throwing here would either
 * fail an otherwise clean run or, worse, invite a catch that silently continues
 * as though the language had been analyzed.
 */
export async function loadGrammarParser(
  name: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<GrammarParserLoad> {
  let state: GrammarPackState
  try {
    state = await inspectGrammarPack(name, env)
  } catch (error) {
    return { status: 'failed', kind: 'digest', reason: (error as Error).message }
  }
  if (state.status === 'absent') return { status: 'absent' }
  if (state.status === 'failed') return { status: 'failed', kind: 'digest', reason: state.reason }

  const language = state.pack.language as SastLanguage
  const artifacts = artifactsByRole(state.pack)
  if ('reason' in artifacts) {
    // The pack verified; the CLI's own pin is malformed. Calling that a digest
    // failure would publish a receipt accusing the user's install of tampering
    // over a defect in this binary.
    return { status: 'failed', kind: 'runtime', reason: artifacts.reason }
  }

  let cached = runtimeCache.get(state.dir)
  if (!cached) {
    cached = buildParser(state, artifacts, language)
    runtimeCache.set(state.dir, cached)
  }
  const result = await cached
  if ('reason' in result) return { status: 'failed', kind: 'runtime', reason: result.reason }
  return { status: 'verified', parser: result.parser, languages: new Set([language]) }
}

/** The artifact names this loader will execute, resolved by role. */
interface PackArtifacts {
  runtime: string
  runtimeWasm: string
  grammar: string
}

/**
 * Which artifact fills which role — by the pin's own `role` field, never by the
 * shape of a file name.
 *
 * `files.find((file) => file.name.startsWith('tree-sitter-'))` returned the
 * FIRST match, so a pack that carried an extra `tree-sitter-evil.wasm` ordered
 * ahead of `tree-sitter-python.wasm` would have had the extra file loaded as the
 * grammar — and the pin verifier that only proved each digest appeared somewhere
 * in the generated file would not have caught the extra entry. Requiring exactly
 * one artifact per role means an ambiguous pack cannot resolve to "whichever one
 * came first"; it does not resolve at all.
 */
function artifactsByRole(pack: PinnedGrammarPack): PackArtifacts | { reason: string } {
  const named = (role: PinnedGrammarFile['role']): string | { reason: string } => {
    const matches = pack.files.filter((file) => file.role === role)
    if (matches.length !== 1) {
      return { reason: `pack declares ${matches.length} artifacts for role ${role}, expected exactly one` }
    }
    return matches[0].name
  }
  const runtime = named('runtime')
  const runtimeWasm = named('runtime-wasm')
  const grammar = named('grammar')
  if (typeof runtime !== 'string') return runtime
  if (typeof runtimeWasm !== 'string') return runtimeWasm
  if (typeof grammar !== 'string') return grammar
  return { runtime, runtimeWasm, grammar }
}

/**
 * A name emscripten can carry around for the runtime WASM that resolves to no
 * file anywhere.
 *
 * `locateFile` is called unconditionally at setup, so it cannot simply throw —
 * but every read of its result is short-circuited by the `wasmBinary` below. A
 * sentinel rather than the real on-disk path means that if a future runtime ever
 * stopped honouring `wasmBinary`, the load would fail loudly instead of quietly
 * reading bytes nobody verified.
 */
const IN_MEMORY_WASM_SENTINEL = '\0codetruss-verified-in-memory\0tree-sitter.wasm'

/**
 * Execute a verified buffer as a CommonJS module.
 *
 * `vm.compileFunction` with the CJS parameter list is what `require()` does
 * internally, minus the file read — which is exactly the part that must not
 * happen. The source compiled here is the Buffer that was hashed, so there is no
 * window between the check and the use at all, and `filename`/`__dirname` still
 * point at the pack so the module's own `require` and any stack trace read the
 * way they would have.
 *
 * Compiling into a module object this function owns also keeps the emscripten
 * `module.exports = Module` clobber out of Node's require cache entirely.
 */
function runVerifiedModule(source: Buffer, filename: string, dirname: string): unknown {
  const compiled = compileFunction(
    source.toString('utf8'),
    ['exports', 'require', 'module', '__filename', '__dirname'],
    { filename },
  )
  const shim = { exports: {} as unknown, id: filename, filename, path: dirname, loaded: false, paths: [] }
  compiled(shim.exports, createRequire(pathToFileURL(filename)), shim, filename, dirname)
  shim.loaded = true
  return shim.exports
}

async function buildParser(
  state: Extract<GrammarPackState, { status: 'verified' }>,
  artifacts: PackArtifacts,
  language: SastLanguage,
): Promise<{ parser: SastParser } | { reason: string }> {
  const runtimeSource = state.contents.get(artifacts.runtime)
  const runtimeWasm = state.contents.get(artifacts.runtimeWasm)
  const grammarWasm = state.contents.get(artifacts.grammar)
  if (!runtimeSource || !runtimeWasm || !grammarWasm) {
    return { reason: 'verified pack did not carry its own bytes' }
  }

  let treeSitterParser: TreeSitterParser
  try {
    const TreeSitter = runVerifiedModule(
      runtimeSource,
      join(state.dir, artifacts.runtime),
      state.dir,
    ) as TreeSitterModule
    if (typeof TreeSitter?.init !== 'function') {
      return { reason: 'grammar runtime did not export a parser' }
    }
    // `wasmBinary` hands emscripten the verified runtime WASM directly, and
    // `Language.load` takes the grammar as a `Uint8Array` — so neither WASM
    // artifact is ever resolved from a path either.
    await TreeSitter.init({ wasmBinary: runtimeWasm, locateFile: () => IN_MEMORY_WASM_SENTINEL })
    const grammar = await TreeSitter.Language.load(new Uint8Array(grammarWasm))
    // One parser instance, reused for every file. A fresh `new Parser()` per
    // file never returns its WASM working memory, which is how the hosted path
    // used to OOM large scans.
    treeSitterParser = new TreeSitter()
    treeSitterParser.setLanguage(grammar)
  } catch (error) {
    return { reason: `grammar runtime failed to load: ${(error as Error).message}` }
  }

  return {
    parser: {
      languages: new Set([language]),
      async parse(lang: SastLanguage, content: string): Promise<ParsedTree | null> {
        if (lang !== language) return null
        if (content.length > MAX_SOURCE_BYTES) return null
        try {
          const tree = treeSitterParser.parse(content)
          if (!tree) return null
          return {
            rootNode: tree.rootNode,
            hasError: tree.rootNode.hasError,
            release: () => {
              try { tree.delete() } catch {}
            },
          }
        } catch {
          return null
        }
      },
    },
  }
}
