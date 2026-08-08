// The published README restated a stale analysis profile id twice, and both
// times the wrong string reached a signed, attested, immutable archive.
//
// `packages/cli/README.md` ships inside the release package — it is one of the
// eight files `verify-release.mjs` byte-compares, the CHANGELOG's peer, and
// `assertChangelogPolicy` guards that peer from the line above this one's call.
// Its profile sentence restates two facts that are derived elsewhere: the
// analysis profile id (`LOCAL_ANALYSIS_PROFILE.id` in `packages/cli/src/types.ts`)
// and the registry analyzer count (`ANALYZERS.length` in
// `packages/analyzer-engine/src/registry.ts`). A restatement is a copy, and this
// copy went stale in 0.2.39 (`local-registry-v3` prose after v4 shipped,
// corrected in 0.2.44) and again in 0.2.53 (`local-registry-v4` prose after v5).
//
// Both escapes have the same shape, and it is not carelessness. The 0.2.53
// commit updated every restatement something checked — the marketing demo
// string, because `tests/marketing-boundary-demo.test.tsx` asserts it contains
// `LOCAL_ANALYSIS_PROFILE.id`, and the receipt page copy, because a zod literal
// in `src/lib/cli-receipts.ts` would not compile without it — and left every
// restatement nothing checked exactly as it was. The difference between the
// strings that were updated and the strings that were not is coverage.
//
// This is the missing coverage for the one restatement that ships to users.

const PROFILE_DECLARATION = /export const LOCAL_ANALYSIS_PROFILE = \{[^}]*?\bid: '([^']+)'/
const ANALYZER_REGISTRY = /export const ANALYZERS: Analyzer\[\] = \[([^\]]*)\]/
const REGISTRY_ENTRY = /^\s*([A-Za-z][\w]*),\s*$/gm

/** Every `local-registry-vN` written down in prose. */
const PROFILE_ID_CLAIM = /local-registry-v\d+/g
/** `15-pass`, `15 registry analyzers`, `15 deterministic registry analyzers`, `15-analyzer`. */
const ANALYZER_COUNT_CLAIM = /\b(\d+)[- ](?:pass(?:es)?|(?:deterministic )?(?:registry |local )?analyzers?)\b/gi

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length
}

/**
 * Read the two derived facts out of their single sources of truth.
 *
 * These are TypeScript constants and this runs under plain Node inside the
 * release build, so the values are extracted textually. That is a seam, so it is
 * fail-closed — an extractor that cannot find exactly what it expects throws
 * rather than returning a guess — and `packages/cli/test/docs-profile-policy.test.ts`
 * imports the real constants and asserts these values equal them, so the
 * extraction cannot drift from what the CLI actually does.
 */
export function readDerivedProfileFacts(types, registry) {
  const declared = PROFILE_DECLARATION.exec(types)
  if (!declared) {
    throw new Error('packages/cli/src/types.ts: cannot read LOCAL_ANALYSIS_PROFILE.id; the docs profile guard has no source of truth')
  }
  const listed = ANALYZER_REGISTRY.exec(registry)
  if (!listed) {
    throw new Error('packages/analyzer-engine/src/registry.ts: cannot read the ANALYZERS array; the docs profile guard has no source of truth')
  }
  const analyzerCount = [...listed[1].matchAll(REGISTRY_ENTRY)].length
  if (analyzerCount === 0) {
    throw new Error('packages/analyzer-engine/src/registry.ts: ANALYZERS parsed as empty; the docs profile guard has no source of truth')
  }
  return { profileId: declared[1], analyzerCount }
}

/**
 * Assert that every profile id and analyzer count written down in `docs` is the
 * one the code actually produces. `docs` is `[{ path, text }]`.
 *
 * Every occurrence must be current: these files describe the release being
 * built, not its history. A doc that needs to name a superseded profile is a doc
 * that needs a decision, not a doc that should quietly pass.
 */
export function assertDocsProfilePolicy(docs, { profileId, analyzerCount }) {
  for (const { path, text } of docs) {
    for (const match of text.matchAll(PROFILE_ID_CLAIM)) {
      if (match[0] === profileId) continue
      throw new Error(
        `${path} line ${lineOf(text, match.index)}: states the analysis profile is \`${match[0]}\`, but `
        + `LOCAL_ANALYSIS_PROFILE.id is \`${profileId}\` (packages/cli/src/types.ts). `
        + 'Update the prose, or bump the profile id back if the prose is what is right.',
      )
    }
    for (const match of text.matchAll(ANALYZER_COUNT_CLAIM)) {
      if (Number(match[1]) === analyzerCount) continue
      throw new Error(
        `${path} line ${lineOf(text, match.index)}: claims "${match[0].trim()}", but the registry has `
        + `${analyzerCount} analyzers (ANALYZERS in packages/analyzer-engine/src/registry.ts). `
        + 'Update the prose, or add the analyzer the prose is counting.',
      )
    }
  }
}
