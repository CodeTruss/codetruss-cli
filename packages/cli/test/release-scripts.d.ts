/**
 * Types for the release scripts the tests drive.
 *
 * `packages/cli/scripts/*.mjs` run under plain node with no build step and are
 * deliberately outside the TypeScript program. These declarations exist only so
 * the tests that exercise them are type-checked like the rest of the suite.
 */
declare module '*/verify-grammar-packs.mjs' {
  export function verifyGrammarPacks(options?: {
    grammarDir?: string
    moduleDir?: string
    pinPath?: string
    lockfilePath?: string
  }): Promise<Array<{ name: string; version: string; files: Array<{ name: string; role: string; sha256: string }> }>>
}

declare module '*/lockfile-integrity.mjs' {
  export function lockfileEntries(lockfile: string, packageName: string): Array<{ version: string; integrity: string }>
  export function lockedSourcePackage(
    lockfile: string,
    packageName: string,
    expectedVersion: string,
  ): { version: string; integrity: string }
}

declare module '*/npm-tarball.mjs' {
  export function readTarballMembers(tarball: Uint8Array): Map<string, Buffer>
  export function verifyRegistrySignature(input: {
    name: string
    version: string
    integrity: string
    signature: { keyid: string; sig: string }
    keys: Array<{ keyid: string; keytype: string; scheme: string; key: string }>
  }): void
}
