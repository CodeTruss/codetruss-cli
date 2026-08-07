/**
 * What the workspace lockfile says about a package a grammar pack is cut from.
 *
 * The pack's provenance (`web-tree-sitter@0.22.6`, `tree-sitter-wasms@0.1.11`)
 * is hand-written in `grammar-pack-sources.mjs` and, until this existed, was
 * checked against nothing: a dependency bump with a stale provenance string
 * would have published a pack that misidentified its own source. Reading the
 * lockfile makes that string an assertion the build can fail on.
 *
 * What a lockfile `integrity` covers is worth being precise about, because it
 * bounds what any check built on it can claim: it is the digest of the packed
 * npm TARBALL, not of the individual files inside it. It cannot be turned into
 * a per-file digest without the tarball itself, which pnpm does not keep — its
 * store is content-addressed per file. Re-deriving a pack's digests from an
 * independently obtained, signed tarball is therefore a network operation and
 * lives in `attest-grammar-sources.mjs`, not in this offline gate.
 */

/**
 * A YAML parser this is not.
 *
 * The lockfile's `packages:` block is machine-generated with a fixed two-space
 * shape, and the alternative — a YAML dependency in a script whose entire job is
 * checking supply-chain claims — adds a package to trust in order to verify
 * packages. Anything this reader fails to understand is reported as "not found",
 * which fails the caller closed.
 */
export function lockfileEntries(lockfile, packageName) {
  const lines = lockfile.split('\n')
  const start = lines.indexOf('packages:')
  if (start === -1) throw new Error('pnpm-lock.yaml has no packages section')

  const entries = []
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index]
    // A non-blank line at column zero is the next top-level section.
    if (line.trim() !== '' && !line.startsWith(' ')) break
    // Scoped names are emitted quoted, because `@types/node@20.1.0:` would
    // otherwise start with YAML's reserved `@`.
    const header = /^ {2}(?:'([^']+)'|(\S+)):\s*$/.exec(line)
    const key = header?.[1] ?? header?.[2]
    if (!key) continue
    // Peer-suffixed keys (`ts-api-utils@2.5.0(typescript@5.9.3)`) carry a second
    // `@` inside the parentheses; drop the suffix before splitting on version.
    const bare = key.replace(/\([^)]*\)$/, '')
    const at = bare.lastIndexOf('@')
    if (at <= 0 || bare.slice(0, at) !== packageName) continue
    const integrity = /integrity:\s*(sha\d+-[A-Za-z0-9+/=]+)/.exec(lines[index + 1] ?? '')
    if (!integrity) continue
    entries.push({ version: bare.slice(at + 1), integrity: integrity[1] })
  }
  return entries
}

/**
 * The single lockfile entry for a package, or an error naming what is wrong.
 *
 * "Exactly one" matters: two resolutions of the same package in one tree means
 * the bytes a pack was cut from depend on which copy the build script's relative
 * path happened to reach, and a provenance string cannot describe that honestly.
 */
export function lockedSourcePackage(lockfile, packageName, expectedVersion) {
  const entries = lockfileEntries(lockfile, packageName)
  if (entries.length === 0) {
    throw new Error(`pnpm-lock.yaml does not pin ${packageName}; grammar pack provenance cannot be checked`)
  }
  if (entries.length > 1) {
    throw new Error(
      `pnpm-lock.yaml resolves ${packageName} to ${entries.length} versions `
      + `(${entries.map((entry) => entry.version).join(', ')}); a grammar pack cannot say which one it was cut from`,
    )
  }
  const [entry] = entries
  if (entry.version !== expectedVersion) {
    throw new Error(
      `grammar pack provenance says ${packageName}@${expectedVersion} but pnpm-lock.yaml pins `
      + `${packageName}@${entry.version}; update GRAMMAR_PACK_PROVENANCE and bump GRAMMAR_PACK_VERSION`,
    )
  }
  return entry
}
