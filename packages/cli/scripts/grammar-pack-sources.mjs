/**
 * What a grammar pack contains, and where its bytes come from.
 *
 * A pack is the tree-sitter machinery the CLI deliberately does NOT ship: the
 * `web-tree-sitter` runtime plus one compiled grammar. Together they are ~722 KB
 * for Python alone, against a 1 MB budget for the entire CLI tarball — which is
 * why the hand-written JS parser exists and why this is a separate, opt-in
 * download rather than a dependency.
 *
 * Every source is a file already pinned in the workspace lockfile at an exact
 * version (no `^`). The pack therefore has no resolution step of its own: the
 * bytes published here are the bytes the hosted audit loads out of
 * `node_modules`, which is what makes the two paths comparable at all.
 */

/**
 * Pack version, bumped independently of the CLI.
 *
 * A pack is immutable once published, exactly like a CLI tarball: changing what
 * `python-1.0.0` means would invalidate every sha256 pinned in an already
 * released CLI. New runtime or grammar bytes require a new version here.
 */
export const GRAMMAR_PACK_VERSION = '1.0.0'

/** Runtime and grammar provenance, recorded so a pack can be traced to a lockfile entry. */
export const GRAMMAR_PACK_PROVENANCE = {
  runtime: { package: 'web-tree-sitter', version: '0.22.6' },
  grammar: { package: 'tree-sitter-wasms', version: '0.1.11' },
}

/**
 * The packs this repository publishes.
 *
 * `language` is the {@link SastLanguage} the pack enables. `files` are copied
 * byte-for-byte; nothing is recompiled, minified or repackaged, so a reviewer
 * can diff a published artifact against `node_modules` directly.
 */
export const GRAMMAR_PACKS = [
  {
    name: 'python',
    language: 'python',
    files: [
      { name: 'tree-sitter.js', source: ['web-tree-sitter', 'tree-sitter.js'] },
      { name: 'tree-sitter.wasm', source: ['web-tree-sitter', 'tree-sitter.wasm'] },
      { name: 'tree-sitter-python.wasm', source: ['tree-sitter-wasms', 'out', 'tree-sitter-python.wasm'] },
    ],
  },
]

/** Directory name a pack is published under, e.g. `python-1.0.0`. */
export function packDirectoryName(pack) {
  return `${pack.name}-${GRAMMAR_PACK_VERSION}`
}

/** Public URL path for one file in a pack. */
export function packFileUrl(pack, fileName) {
  return `/downloads/grammars/${packDirectoryName(pack)}/${fileName}`
}
