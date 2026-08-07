# Changelog

CodeTruss CLI follows semantic versioning. Release artifacts and their SHA-256
checksums are published at <https://codetruss.com/downloads/codetruss-cli-latest.json>.

## Unreleased

## 0.2.30 — 2026-08-06

- Publish the 0.2.25 through 0.2.29 release history, which shipped without
  changelog entries. No CLI behaviour changed. `CHANGELOG.md` is one of the eight
  published files and is byte-compared against the immutable release archive, so
  documenting those releases requires a new version rather than an edit in place.

## 0.2.29 — 2026-08-06

- Say plainly that a local run never checks for injection. The coverage
  analyzer had stayed silent for TypeScript, JavaScript, and Python because the
  SAST engine supports those languages — a fact about the engine, not about a
  run that never executes it. Analyzers now receive the non-registry passes in
  effect, defaulting to none, and a repository holding at least 300 lines that
  pass would have covered gets one INFO finding naming the classes nobody
  looked for: SQL injection, command injection, code injection, path traversal,
  SSRF, open redirect, XSS, and insecure deserialization.
- Replace the receipt's "Hosted Health scores: N/A" footnote with a "What did
  not run" section naming SAST, the hosted symbol graph, the scores, and — when
  no model read the diff — the optional LLM review as detection gaps, and
  stating that a PASS verdict is not a claim the change is secure.
- Keep receipts written by 0.2.28 and earlier verifiable. No signed field
  changed, only the rendering, so each superseded wording stays byte-reproducible
  for verification.

## 0.2.28 — 2026-08-06

- Let `codetruss setup --yes` finish protecting an ordinary repository instead
  of exiting 3 with a policy file and no guardrail. Conventional source roots
  that exist on disk are now adopted unattended, never a repository-wide glob,
  and the adopted list is printed so the decision stays auditable. With nothing
  detectable the run still stops and asks.
- Leave auto-detected verification commands out of the policy on an unattended
  run instead of aborting, and print how to enable them. A recorded but
  untrusted command list makes every later review exit 3 with no receipt, so the
  previous behaviour produced a repository that was configured, hooked, and
  permanently blocked. Withholding applies only when hooks are being installed;
  `--hooks none` still records the commands for inspect-then-trust.

## 0.2.27 — 2026-08-06

- Deduplicate the PostToolUse fast scope check per turn. The first notice for a
  path arrives exactly as before, repeats are silent, and a new path still
  speaks immediately; a turn that touched one out-of-scope file a dozen times
  previously emitted a dozen identical warnings.
- Keep that deduplication fail-soft: when session or turn state cannot be read
  or written, every warning is emitted as it was before.

## 0.2.26 — 2026-08-06

- Keep the receipt's Task line readable when an agent harness delivers a machine
  event — a background-task notification or a tool result — on the same prompt
  channel as human instructions. A human prompt is preserved exactly as written;
  a structured event is reduced to its event tag and summary. Derivation stays
  deterministic, so prompt-time turn binding is unaffected.
- Report credential-shaped placeholders at INFO instead of skipping them in
  silence, so a deliberate skip is not mistaken for a scanner that detects
  nothing. Only values that announce themselves as fake qualify; runtime
  credential references such as `process.env`, `{{...}}`, and `ENV[]` stay
  silent, because that is how a credential is supposed to be written.

## 0.2.25 — 2026-08-06

- Stop an immaterial index-coverage gap from failing a receipt. When the index
  measurably covered at least 95% of its analyzable input, the remaining
  limitations — an oversized lockfile, an unreadable file — are reported as
  review-level context instead of incomplete evidence. Larger losses, and a
  truncated file walk, still fail closed.
- Accept a set of pinned signers. `signing.publicKeys` holds one key per
  developer, `codetruss verify-policy trust-key` appends the local key to it,
  and receipt verification accepts any trusted signer, so a teammate signs as
  themselves instead of sharing a private key and destroying attribution.
- Report the verification commands `codetruss init` detected and state that they
  are not trusted until approved. Without that notice the next `review` exits 3
  with no receipt at all.
- Stop reporting test and seed credentials as HIGH: Go, Python, and Ruby test
  file conventions are recognized, and a database seed script gets its own
  MEDIUM finding about the seed path reaching a production database rather than
  a rotate-immediately instruction.
- Stop reporting prose as a credential. Values carrying internal whitespace
  under a credential-shaped key (validation messages, translations, UI labels),
  SCREAMING_SNAKE enum members, `{{...}}` templates, and environment reads are
  no longer leaks.
- Exclude minified and bundled assets by mean line width rather than filename,
  and report the excluded volume in KB as well as LOC, since packed output
  understates its size in lines. Excluding a file no longer manufactures dead
  code for the files it imports.
- Recognize more convention-loaded entry points as reachable: Pages Router
  routes, Storybook stories, tooling dotfiles, and `package.json` script targets
  are no longer reported as orphaned.
- Suppress the duplicate "no `.env.example`" nudge when a committed runtime
  `.env` already produces the structure analyzer's version of that finding, and
  reword the per-language security caveat from "surface-only" to "coverage is
  partial", since pattern and dataflow rules do apply beyond TypeScript,
  JavaScript, and Python.

## 0.2.24 — 2026-07-15

- Ship the guided setup, local evidence privacy, invocation provenance,
  aggregate metrics, reproducible packaging, and Windows setup corrections
  accumulated in the unpublished 0.2.15 through 0.2.23 candidates.
- Enforce exact owner-only permissions for existing and newly created local
  evidence directories, including restrictive-umask environments.
- Make hook health, verification fingerprints, and command-line validation
  fail closed without rejecting healthy pre-commit-only configurations.

## 0.2.23 — 2026-07-14 (unpublished)

- Ship the guided setup, local evidence privacy, invocation provenance,
  aggregate metrics, reproducible packaging, and Windows setup corrections
  accumulated in the unpublished 0.2.15 through 0.2.22 candidates.

## 0.2.22 — 2026-07-14 (unpublished)

- Resolve Windows package-manager shims through shell-free PATH/PATHEXT
  inspection before the first public release of the guided setup changes.

## 0.2.21 — 2026-07-14 (unpublished)

- Detect `pnpm`, `npm`, and `yarn` command shims correctly during guided setup
  on Windows.
- Make cross-platform hook tests provision the persistent local CLI that the
  production hook installer intentionally requires.

## 0.2.20 — 2026-07-14 (unpublished)

- Ship the guided setup, local evidence privacy, hook guidance, invocation
  provenance, aggregate local metrics, and reproducible-build hardening from
  the unpublished v0.2.15 through v0.2.19 candidates.
- Correct the candidate release history before publishing these changes for the
  first time.

## 0.2.19 — 2026-07-14 (unpublished)

- Preserve the privacy, setup, and reproducible-build hardening from the
  unpublished v0.2.18 candidate.
- Give a repository that already completed setup the next relevant automatic
  hook action after its first receipt instead of sending it through setup again.

## 0.2.18 — 2026-07-14 (unpublished)

- Preserve the privacy protection, guided setup, and deterministic release
  hardening from the unpublished v0.2.17 candidate.
- Make bundled release bytes independent of both the physical workspace path
  and the directory from which the build command is invoked, with byte-for-byte
  regression coverage across package and repository working directories.

## 0.2.17 — 2026-07-14 (unpublished)

- Preserve the privacy protection, guided setup, and cross-platform hook
  diagnostics from the unpublished v0.2.16 candidate.
- Make bundled release bytes independent of whether a workspace dependency tree
  is physical or symlinked, after the immutable artifact verifier caught the
  same source producing path-dependent esbuild labels across two worktrees.

## 0.2.16 — 2026-07-14 (unpublished)

- Add `codetruss setup`, a guided local-only path that proposes scoped source
  roots, displays detected verification commands and their exact trust
  fingerprint, installs automatic checks, runs hook health diagnostics, and
  calls out the remaining one-time Codex `/hooks` approval.
- Make first-receipt guidance match the actual verdict and direct future
  automation through the one-command setup path.
- Keep receipts, raw patches, signatures, temporary receipt files, and the
  generated agent runner out of Git through a verified local exclude rule;
  fail closed for tracked evidence, conflicting ignore rules, or unsafe Git
  metadata paths.
- Recognize symlinked local `node_modules` installations in isolated verifier
  snapshots and allow manual trusted checks up to five minutes while retaining
  the shorter shared automatic-hook work budget.
- Surface the actionable verifier error when a hook cannot produce a receipt.

## 0.2.15 — 2026-07-14 (unpublished)

- Record typed manual, pre-commit, and Claude/Codex hook invocation provenance
  on new signed receipts while keeping older receipt-v1 files and explicit sync
  compatible.
- Add `codetruss metrics --json`, a network-free aggregate over verified local
  receipts with aggregate UTC dates, active-day count, verdict, invocation,
  D7 receipt-pattern, and hook-health fields only.
  It emits no repository, task, path, finding, command, diff, receipt ID, or
  signing-key data.

## 0.2.14 — 2026-07-14

- Give the deterministic CycloneDX SBOM a canonical UUIDv5 serial number and
  enforce that identity in release verification, making the SBOM directly
  compatible with GitHub artifact attestations without weakening reproducible
  package bytes.
- Retain the complete v0.2.13 Windows long-path and installer hardening in a new
  immutable candidate after GitHub rejected the prior candidate's otherwise
  valid SBOM because it did not carry a top-level serial number.

## 0.2.13 — 2026-07-14 (unpublished)

- Enable Git for Windows long-path support command-locally for every
  CodeTruss-owned Git process and generated hook entry point. Exact private
  evidence now remains usable in deep checkouts without changing the user's
  repository or global Git configuration.
- Preserve the complete v0.2.12 SBOM, authentication-network-contract, hook,
  verifier-isolation, and local-evidence hardening in a new immutable release
  after the Windows compatibility matrix rejected the prior candidate.
- Release publication retained this candidate without downloadable assets after
  GitHub's SBOM attestation action required a top-level CycloneDX serial number.
  v0.2.14 carries the deterministic identity fix.

## 0.2.12 — 2026-07-14 (unpublished)

- Preserve the complete v0.2.11 hook, Windows, verifier, and exact-evidence
  hardening without replacing that candidate's immutable versioned bytes.
- Emit canonical Package URLs for scoped npm components in the deterministic
  CycloneDX SBOM so registry and vulnerability tooling can match them.
- Correct the authentication network contract: `auth status` verifies the
  saved credential with CodeTruss, while `auth logout` revokes it before
  deleting the local copy; neither command sends repository data or receipts.
- Release review retained this candidate without publication after the Windows
  matrix exposed a remaining Git `MAX_PATH` failure in deep private-evidence
  directories. v0.2.13 carries the command-local long-path fix.

## 0.2.11 — 2026-07-14 (unpublished)

- Make agent hooks fail closed when exact baseline evidence, state locks, the
  installed runner, or the local review process fails. A failed first Stop asks
  for one repair turn; an already-active Stop reports the result without
  creating an infinite continuation loop.
- Preserve retryability before final evidence is frozen and durably replay a
  completed exact result after post-review transport failures, so a transient
  crash cannot poison state or silently rerun a completed review.
- Bound the full hook pipeline inside its host deadline, terminate timed-out
  verifier process trees, fairly allocate the remaining command budget, and
  retain bounded head/tail output when a trusted verifier is noisy.
- Normalize Windows Git evidence against its native `NUL` sentinel, canonicalize
  filesystem aliases before private-object-store containment checks, keep hook
  state below native path limits, and keep the verifier deadline armed while
  descendant-held output pipes remain open.
- Keep hosted analyzer indexing historically identical while enabling explicit
  binary-aware local CLI indexing for archives, fonts, and WebAssembly assets.
- Include the hook-state migration and deterministic release-policy hardening
  from the unpublished 0.2.6 through 0.2.10 candidates.
- Release review rejected this candidate before publication because its SBOM
  encoded scoped npm package slashes noncanonically. The immutable artifact was
  retained; v0.2.12 carries the corrected metadata.

## 0.2.10 — 2026-07-14 (unpublished)

- Freeze the hook-state migration only after its full-key precedence, candidate
  collision cleanup, and empty legacy-root removal regressions passed. This
  prevents the release artifact from racing the final privacy hardening.
- Include the migration and independent package-policy enforcement from the
  unpublished 0.2.9 candidate.
- Independent release review rejected this candidate before publication after
  finding that some Stop-hook operational failures did not block and that
  verifier timeouts did not yet terminate the complete descendant process tree.

## 0.2.9 — 2026-07-14 (unpublished)

- Move compact hook state to a new versioned layout and explicitly retire the
  legacy 64-character state tree, including owned private Git object stores, so
  an upgrade cannot orphan captured task text or source evidence.
- Enforce a release-package policy independently from byte reproducibility:
  fixed package identity and source links, no runtime dependency declarations,
  no install lifecycle scripts, and matching CycloneDX component identity.
- Include the Windows path, cross-platform reproducibility, and strict release
  verifier hardening from the unpublished 0.2.8 candidate.

## 0.2.8 — 2026-07-14 (unpublished)

- Byte-compare the complete packaged manifest, including lifecycle scripts and
  dependency metadata, and require canonical release metadata and checksum
  sidecars so a refreshed-but-tampered release cannot pass local verification.
- Bound private agent-hook state components to 96-bit hashed path keys and use
  compact snapshot directories so exact evidence remains reliable under
  Windows path limits; run CLI subprocess coverage through Node on every OS.
- Force LF source checkout across platforms, reject non-regular release inputs
  even where symlink creation is unavailable, and include all deterministic
  packaging and verifier hardening from the unpublished 0.2.7 candidate.

## 0.2.7 — 2026-07-14 (unpublished)

- Strictly verify the custom release envelope independently from the writer:
  gzip framing, stored blocks, CRC32, ISIZE, USTAR magic, checksums, ownership,
  modes, ordering, padding, terminators, exact entries, and `package.json.files`.
- Add boundary and corruption regressions, reject symbolic/non-regular package
  inputs, enforce a 1 MB archive budget, and require every operating-system and
  Node compatibility job to rebuild and match the immutable website archive.
- Keep engine enforcement strict on Node 22/24 while using a dev-dependency-only
  override on Node 20.9; installed release archives receive no engine override.
- Include the deterministic packaging change from the unpublished 0.2.6
  candidate.

## 0.2.6 — 2026-07-14 (unpublished)

- Replace `npm pack` release construction with a deterministic USTAR writer and
  platform-independent stored-gzip encoder over the exact eight published
  files. Website, GitHub Actions, provenance, and npm now verify one byte-for-byte
  archive regardless of npm version, zlib build, or operating system.
- Separate Node.js 20.9 runtime smoke coverage from source-test coverage now that
  modern Vitest requires a newer Node release. Node 20.9 still builds, installs,
  verifies, and exercises the packaged CLI; Node 22 and 24 run the full source
  suite.
- Include the verifier-isolation, baseline-repair, and lint-race hardening from
  the unpublished 0.2.5 candidate.
- Public release review held this candidate before publication until the custom
  format had an independent strict verifier and cross-platform SHA coverage.

## 0.2.5 — 2026-07-14 (unpublished)

- Keep final analysis, diff, and verifier evidence fail-closed while allowing a
  repair to advance when an incomplete baseline becomes complete in the final
  tree. The resolved historical limitation is explicit and forces
  `REVIEW_REQUIRED`; it can never produce `PASS`.
- Include the external verifier isolation and binary-evidence hardening from the
  unpublished 0.2.4 candidate.
- Dogfood and public CI rejected this candidate before release after finding a
  transient lint race and platform-specific `npm pack` archive metadata.

## 0.2.4 — 2026-07-14 (unpublished)

- Run each trusted verification command from a fresh immutable source tree
  outside the live repository, strip repository-local Git hook variables, and
  stop Git discovery at the snapshot boundary. Verifiers cannot accidentally
  read or mutate the parent checkout or inherit CodeTruss private-object access.
- Reuse ignored installed Node dependencies through an explicit link while
  keeping verifier source writes isolated, with an end-to-end regression that
  proves exact staged bytes, dependency availability, Git-environment cleanup,
  and live-repository isolation.
- Classify common archives and binary assets without treating them as incomplete
  source evidence, and replace a raw NUL byte in existing TypeScript source with
  its equivalent escaped representation.
- Include the reproducible public-source release workflow from the unpublished
  0.2.2 and 0.2.3 candidates.
- Dogfood rejected this candidate because a repaired baseline-only binary-text
  limitation was still treated as an unresolvable final-evidence failure.

## 0.2.3 — 2026-07-14 (unpublished)

- Make the repository's ignored installed Node toolchain available inside each
  fresh, immutable verification source snapshot, so trusted project commands
  such as `pnpm test` run against exact evidence without sharing source writes
  between verifiers.
- Treat release archives and common binary assets as assets during indexing,
  preventing packaged CLI artifacts from creating false incomplete-evidence
  failures.
- Include the reproducible public-source release workflow from the unpublished
  0.2.2 candidate. Dogfood rejected this candidate after exposing inherited Git
  hook state inside verification commands.

## 0.2.2 — 2026-07-14 (unpublished)

- Rebuild the distributable from the clean, locked workspace dependency graph
  and require the public-source release workflow to reproduce the exact website
  archive before attestation.
- Include the hook protocol and doctor hardening from the unpublished 0.2.1
  release candidate.

## 0.2.1 — 2026-07-14 (unpublished)

- Align Claude Code and Codex hook responses with each host's current hook
  protocol: invalid prompt capture blocks explicitly, edit feedback reaches the
  agent as model context, and a failed stop check requests one repair turn.
- Prevent stop-hook retry loops by degrading an already-active failed stop check
  to visible feedback instead of requesting another continuation.
- Make `hooks doctor` verify the installed runner and policy while clearly
  surfacing Codex's required one-time, hash-specific `/hooks` trust review.

## 0.2.0 — 2026-07-14

- Build every new receipt from one immutable baseline-to-final Git evidence pair,
  including exact pre-agent dirty and untracked bytes, stable start/end commits,
  and the two evidence-tree object IDs. Synthetic evidence stays in a disposable
  private object database instead of the repository object database.
- Freeze staged and working-tree review targets before analysis. Each verification
  command now receives a fresh materialization of the same final tree, so one
  verifier cannot mutate the evidence observed by the next; private Git and hook
  capabilities are stripped before repository commands run.
- Harden optional local LLM review. Claude and Codex receive the bounded task and
  diff through standard input only, run without tools or persistent sessions, and
  are bounded by time, output, and descendant-process cleanup. Diff content still
  goes directly to the developer-selected provider and never to CodeTruss.
- Add prompt-frozen Claude Code and Codex turn hooks with exact private snapshots,
  authenticated task and policy context, fast edit-time scope feedback, and one
  full receipt at Stop. Hook installation is transactional, `hooks doctor` reports
  actionable configuration/runtime failures, and pre-commit distinguishes review
  findings from blocking failures.
- Add a signed policy SHA-256 covering effective scope, verification-command
  digests, and LLM settings without copying raw verification commands into synced
  receipts. Evidence truncation or incomplete analyzer coverage still fails closed.
- Add browser-approved, receipt-only `auth login`, `status`, and `logout`; explicit
  `sync` remains the only upload path. Synced History receipts retain signer
  credential lifecycle status and support append-only reviewer annotations.
- Harden staged, working-tree, unborn-repository, large-diff, linked-worktree,
  SHA-256 repository, symlink, gitlink, and verification evidence paths.
- Ship a deterministic CycloneDX SBOM with the package and versioned download, plus
  checksums and release metadata for GitHub artifact-attestation/provenance
  verification. Publication and attestation remain explicit release operations.

## 0.1.1 — 2026-07-13

- Initial local-first CLI preview.
- Scope allow/deny policy and sensitive-surface classification.
- Shared deterministic analyzer registry and project verification commands.
- Markdown and integrity-signed JSON receipts with explicit verdict reasons.
- Explicit privacy-minimized receipt sync and optional direct-provider LLM review.
