import { chmod, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { generateSbom } from './generate-sbom.mjs'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = join(packageDir, 'dist')
const outfile = join(outDir, 'cli.cjs')

await rm(outDir, { recursive: true, force: true })
await build({
  absWorkingDir: packageDir,
  entryPoints: [join(packageDir, 'src', 'cli.ts')],
  bundle: true,
  platform: 'node',
  target: 'node20.9',
  format: 'cjs',
  // Keep module identity and emitted source labels relative to the logical
  // workspace. Without this, esbuild resolves a symlinked node_modules tree to
  // its physical worktree and produces different release bytes from the same
  // source and dependency graph.
  preserveSymlinks: true,
  // Whitespace only — never identifier or syntax minification.
  //
  // The release archive is capped at 1 MB and packed with STORED deflate blocks
  // for byte-reproducibility, so every source byte costs a byte. Shipping the
  // SAST engine locally added ~230 KB of real code and left ~17 KB of headroom,
  // which no further release could survive. Collapsing indentation recovers
  // ~230 KB while changing nothing that matters: identifiers keep their names,
  // so stack traces still name functions; `legalComments: 'eof'` is unaffected
  // (and this dependency graph emits none); and the transform is deterministic,
  // so reproducible builds hold. Syntax and identifier minification are NOT —
  // they would rewrite the code a security tool is supposed to be auditable in.
  minifyWhitespace: true,
  legalComments: 'eof',
  outfile,
})

// esbuild includes resolved source labels in its otherwise deterministic output.
// pnpm may place these ESM-only glob dependencies at the workspace root or the
// package root depending on unrelated workspace dependencies. Normalize their
// comment labels without changing executable code or stack-bearing CommonJS
// module names, so the release bytes do not depend on hoisting collisions.
//
// Whitespace minification already strips these labels, so this is currently a
// no-op. It stays because it is the guard, not the symptom: reverting
// minification must not silently reintroduce hoisting-dependent release bytes.
const bundle = await readFile(outfile, 'utf8')
const normalizedBundle = bundle.replace(
  /^(\/\/ )(?:(?:\.\.\/)+)?node_modules\/(?:\.pnpm\/[^/]+\/node_modules\/)?((?:balanced-match|brace-expansion|minimatch)\/)/gm,
  '$1node_modules/$2',
)
await writeFile(outfile, normalizedBundle, 'utf8')
await chmod(outfile, 0o755)
await generateSbom()
