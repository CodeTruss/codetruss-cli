// Canonical release identity. The published manifest is byte-compared by
// `verify-release.mjs`, so the builder, the verifier, and the verifier's own
// tests must all derive it from this module rather than restating it.

export const CLI_REPOSITORY_SLUG = 'CodeTruss/codetruss-cli'
export const CLI_REPOSITORY_URL = `https://github.com/${CLI_REPOSITORY_SLUG}`

// The CLI repository moved from the `DeliriumPulse` account to the `CodeTruss`
// organisation on 2026-08-07. Releases followed the transfer, and every release
// still in circulation has since been re-attested under the organisation, so one
// command covers all of them. The transferred `--repo DeliriumPulse/…` slug
// returns HTTP 404 and must never be advertised.
//
// This deliberately does NOT vary by version. It did briefly, because the
// artifacts built before the move were only attested under the building account
// and needed `--owner DeliriumPulse --signer-workflow …`. Re-attestation removed
// that split; keeping the branch would have published the weaker command for
// versions the simple one now verifies, and contradicted the release notes,
// which print only this form.

/** The `gh` invocation that verifies any published artifact's provenance. */
export function attestationCommand(artifactName) {
  return `gh attestation verify ${artifactName} --repo ${CLI_REPOSITORY_SLUG}`
}

/** The canonical `codetruss-cli-latest.json` body, in its byte-compared key order. */
export function buildReleaseManifest({ pkg, sha256, sbomSha256 }) {
  const versionedName = `codetruss-cli-${pkg.version}.tgz`
  return {
    name: pkg.name,
    version: pkg.version,
    url: `/downloads/${versionedName}`,
    latestUrl: '/downloads/codetruss-cli-latest.tgz',
    sha256,
    sbomUrl: `/downloads/codetruss-cli-${pkg.version}.sbom.cdx.json`,
    sbomSha256,
    node: pkg.engines.node,
    repository: CLI_REPOSITORY_URL,
    releaseUrl: `${CLI_REPOSITORY_URL}/releases/tag/v${pkg.version}`,
    attestationCommand: attestationCommand(versionedName),
  }
}

/** Serialised exactly as the published manifest is written and compared. */
export function serialiseReleaseManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`
}
