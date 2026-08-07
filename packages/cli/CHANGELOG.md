# Changelog

CodeTruss CLI follows semantic versioning. Release artifacts and their SHA-256
checksums are published at <https://codetruss.com/downloads/codetruss-cli-latest.json>.

## Unreleased

## 0.2.40 — 2026-08-07

- **Python can now be analyzed locally, if you ask for it.** `codetruss
  grammars install python` downloads the `web-tree-sitter` runtime and the
  compiled Python grammar (722 KB) into your data directory — XDG on macOS and
  Linux, `LOCALAPPDATA` on Windows. Nothing is bundled in the tarball, nothing
  is fetched during an analysis, and no other command installs it for you. The
  CLI ships a hand-written JavaScript parser precisely because these grammars
  are several times its entire release budget, and that trade is unchanged for
  anyone who does not run this command. `codetruss grammars list|status|
  uninstall` round out the group; `status` exits non-zero when a pack is
  missing or fails verification, so it can gate a setup script.
- **The pack is pinned, verified as it arrives, and verified again every time
  it is loaded.** Each artifact's SHA-256 is compiled into the CLI at build
  time. The download is hashed as it streams, with the pinned length enforced
  mid-stream so a wrong or hostile origin cannot write an unbounded file to
  disk; artifacts land in a scratch directory and are moved into place only
  after every one of them verifies, so a pack directory is never half-installed.
  The only download origin is `codetruss.com` — no third-party CDN, and
  redirects are refused. Hashing is streamed in-process, never shelled out to
  `shasum` or `Get-FileHash`. **Every** failure — absent, truncated, over-long,
  wrong digest, unreadable, or an unexpected extra file in the pack directory —
  resolves to "pack unavailable", and the run reports Python as skipped. There
  is no path on which unverified bytes are executed.
- **Python runs the complete rule pack, not the reduced JavaScript subset.**
  That subset exists because a hand-written parser might disagree with
  tree-sitter, and only rules proven to agree were admitted. A grammar pack *is*
  the hosted parser and the hosted grammar, so there is no divergence to guard
  against — and narrowing it would report less than the same code receives in a
  hosted scan, for no gain in precision. Command injection, path traversal,
  SSRF and insecure deserialization are checked in Python locally; they remain
  unchecked in JavaScript, TypeScript and TSX, and the receipt keeps saying so.
- **Verified against the hosted path over 233 real Python files** — the
  full-stack FastAPI template, three further repositories, and a synthetic
  fixture covering each rule class. Both parsers produced the same 11 findings,
  with **zero divergence in either direction**.
- **Receipts move to the `local-registry-v4` profile, which states what the run
  actually did about Python.** The pass set is unchanged from v3; the wording
  had to change, because v3 says flatly that the local pass covers "JavaScript,
  TypeScript and TSX only" and that Python received no security analysis, and
  that is false whenever a pack is installed. There are now three
  distinguishable statements instead of one frozen sentence: **absent** names
  the Python file count and the command that would cover them, **verified**
  names the rule pack and the file count while keeping the JavaScript subset's
  limits scoped to JavaScript, and a **failed** pack now says *which* kind of
  failure it was — a digest mismatch (the pack does not match what this CLI
  published, so reinstall), a runtime that would not start on this machine even
  though the digests matched, or a scan that threw partway and had its partial
  results discarded. Only a real digest mismatch renders the tampering sentence;
  an out-of-memory error no longer accuses your install of not matching the
  published digests. Every failure branch closes with the provable "No findings
  from this pack were reported" in place of the wider absolute claim.
  `local-registry-v3` keeps a frozen renderer, so receipts signed by 0.2.39
  still verify byte-for-byte.
- **The bytes that are verified are now the exact bytes that execute.** The
  loader used to hash each artifact by path and then re-open the same path to
  `require()` it, so the file that was hashed and the file that ran were two
  separate reads with a window between them — three digests and a directory
  listing wide enough for another process with write access to the pack
  directory to swap a hostile `tree-sitter.js` in after the check and have it
  executed. `inspectGrammarPack` now reads each artifact once and returns the
  buffer it hashed; the runtime is compiled from that buffer and the two WASM
  artifacts are handed to `web-tree-sitter` as in-memory `Uint8Array`s
  (`wasmBinary` and `Language.load`), so nothing is ever resolved from a path a
  second time. Artifacts are opened `O_NOFOLLOW` and rejected unless they are
  regular files; a symlinked pack root, a pack root not owned by the current
  user, or one writable by group or other is refused, and a loose root created
  by an earlier CLI is tightened to `0700` on install. A local same-user race
  that reliably executed attacker code against the previous loader now fails
  every attempt.
- **Fixed: Python was silently dropped from the second half of every review.**
  The tree-sitter runtime reassigns its own entry in Node's module cache while
  initializing, so loading it a second time in one process returned the wrong
  object. A review analyzes twice — once for the baseline tree, once for the
  final tree — which meant the final analysis quietly failed to load the grammar
  and reported Python as unanalyzable even with a healthy pack installed. The
  runtime is now loaded once per process. Digests are still re-checked on every
  load; only the runtime construction is reused.
- **Fixed: the Windows data directory was resolved with POSIX path rules.**
  `LOCALAPPDATA` was checked with a path test that treats `C:\Users\…` as
  relative anywhere other than Windows, which made the branch correct on Windows
  and unverifiable everywhere else. It now names the Windows path flavour
  explicitly, and is covered by a test that runs on every platform.

## 0.2.39 — 2026-08-07

- **Two analyzers join the registry, which now holds 15.** Both come from a
  design study that ran candidate rules against eight real repositories and
  kept only what survived. Everything they emit is `INFO` or `LOW`, and
  `computeVerdict` escalates only at `MEDIUM`, so **neither can turn a PASS into
  a REVIEW_REQUIRED or a FAILED**. A comment that repeats the line below it is
  not a reason to stop an agent mid-turn.
- **Comment Signal (`comment-slop`)** measures each file against the
  repository's own commenting baseline. It reports a file carrying three or more
  standalone single-line comments whose words already appear on the statement
  beneath them, and a file carrying two or more comments that narrate an edit
  (`// Updated to use the new auth middleware`), address the reader, claim
  credit for the code, or describe the work as provisional (`// In a real app
  you would verify this`) — the last of which no TODO scan can see, because it
  carries no marker. Comment *density* is reported as a metric and is never a
  finding: across the study the most densely commented codebase produced zero
  restating comments and the sparsest produced sixty-one, so a density rule
  would penalise exactly the code worth rewarding. Tests, generated and
  vendored content, scaffolded config, migrations, licensed files, and files
  under 25 code lines are all out of scope, and the analyzer covers only the
  eleven languages it has a comment lexer for.
- **Speculative Structure (`overengineering`)** reports exported values that
  appear in no other indexed file, tests included, and `catch` blocks whose
  entire body logs an error and rethrows it unchanged. Export findings are
  worded as candidates because a symbol reached through a dynamic import or a
  path built from strings looks identical to this pass. The rule is
  barrel-aware, skips ORM schema modules, framework convention exports, runner
  and Pages Router paths, and does not run at all against a library, whose
  exported surface is its product.
- **A Convex deployment is not a pile of exports nobody consumes.** Convex
  bundles a functions directory and addresses its modules by path at runtime, so
  `export` *is* the registration and the only reference is a string no static
  pass can follow. Those directories are now excluded, detected from the
  toolchain rather than the directory name — Convex allows renaming it, and its
  modules are commonly imported through a path alias no specifier match would
  catch. Two structural signals are required together: the `convex` dependency
  in a manifest, and the `_generated/{api,server}` pair that `convex dev` emits
  into the deployment root. A directory merely *named* `convex` is still swept.
- **Speculative Structure states what it cannot see.** Single-implementation
  interfaces, options nobody overrides, and parameters never varied at any call
  site need the cross-file symbol graph, which does not run locally. The
  receipt's "What did not run" block now names them, because silence there would
  read as "no over-engineering found".
- **Receipts disclose the new count without rewriting the old ones.** The local
  analysis profile becomes `local-registry-v3`. Receipts signed under
  `local-registry-v2` keep a frozen renderer that reproduces their
  "13 deterministic registry analyzers" wording byte for byte, exactly as
  `local-registry-v1` receipts already did, so every receipt on disk still
  verifies. Only v3 receipts say 15. The hosted receipt schema accepts all three
  profile versions and rejects any fourth.
- A new **Comment signal** section on the receipt reports the repository's
  median comment ratio, how many comments restate or narrate, and how many
  files carry enough of either shape to be reported. It counts comments and
  reports files, and says which is which: a file holding two restating comments
  is under the reporting threshold, and a receipt that called it clean on that
  basis would be stating something untrue. It is rendered from pass metrics
  rather than findings — a
  repository-level "nothing restates the code" finding fingerprints identically
  in the baseline and final trees, so the delta would file it under recurring
  and it could never reach a hook receipt. The section emits nothing when those
  metrics are absent, so receipts signed before this release render unchanged.

## 0.2.38 — 2026-08-07

- **A lone changed file no longer seats its own directory as inferred scope
  while the turn is inferring scope elsewhere.** With no allow globs configured,
  the working-set rule let a single file establish its parent directory as a
  root. On a turn touching several directories with one file each, every
  directory it touched vouched for itself, so scope drift — the detection that
  runs on an unconfigured first run — could not fire at all. The scope was being
  read off the very change it was meant to judge. Measured on the 0.2.36
  teardown fixture: `codetruss review --task "Add free-text search to the task
  list endpoint"` with no `.codetruss.yml` and no `--allow` called the unrelated
  `src/lib/billing.ts` in scope and reported no drift, while the same fixture
  under `--allow 'src/routes/**'` named it correctly.
- The single-file allowance stays, narrowed to what it was introduced as in
  0.2.32: the whole turn's fallback, not a grant each directory can claim for
  itself. It now applies only when admitting it would be the turn's **only**
  inferred root — no approved allow root, no root the task already named, and
  one candidate directory. A lone file beside any other inferred scope is drift
  again. A cluster of two files still stands on its own evidence, and a
  directory the task names by feature is still reached without it.
- Verdicts change only for that shape: an unconfigured turn whose changed files
  spread across several directories with too few files to cohere. Turns with
  configured allow globs are untouched, and so is the archetypal first-run case
  the allowance exists for — one file, or one directory, with nothing else
  inferred. Receipts disclose `inferred` classifications exactly as before: the
  classification, its bases, the receipt schema, and every signed Markdown
  rendering are unchanged, so receipts already on disk verify byte for byte.

## 0.2.37 — 2026-08-07

- **A process tree whose leader already exited is never force-killed on
  Windows.** Verification and local-provider cleanup ran
  `taskkill /pid <leader> /t /f` from the child's own exit handler — where the
  leader is dead by definition — and from the timeout path after the leader had
  exited. Windows recycles a freed pid within milliseconds, so that force-kill
  could land on an unrelated process that had just inherited the number; it is
  what killed a freshly forked vitest worker mid-run in CI. Both call sites now
  gate on liveness read from our own `ChildProcess` handle, which pid reuse
  cannot misdirect. Nothing is lost by skipping: `taskkill /t` enumerates the
  tree from the leader, so a dead leader could not have reached a descendant
  anyway.
- The escaped-descendant test closed the same vector in its own cleanup. It
  SIGKILLed the pid recorded in a pidfile, and once the deadline had already
  reaped the tree that pid could belong to an innocent process — a liveness
  probe cannot tell a recycled pid from a live descendant. The descendant now
  exits on its own when a sentinel file disappears, so cleanup signals no
  recorded pid at all.
- **The release build now reads the changelog it ships.** `pnpm cli:release`
  fails unless the version being built has its own `## <version> — <date>`
  heading and every release heading forms one unbroken descending chain — each
  version exactly once, in order, no gaps, and nothing stranded above the newest
  entry.
- Repairs the changelog that guard was written for: CLI 0.2.36 overwrote
  `## 0.2.35 — 2026-08-07` with its own heading, leaving the entire local-SAST
  release's notes orphaned under 0.2.36 and erasing 0.2.35 from the history.
  Both entries are now restored to what each release actually shipped.

## 0.2.36 — 2026-08-07

- **Indexed file paths are now the same bytes on every platform.** The
  repository walk emitted whatever separator the host used, so a Windows run
  produced `src\users.ts` while every other path surface in the CLI — receipts,
  git snapshots, policy globs, scope inference — normalized to `src/users.ts`.
  Three consequences, all fixed by normalizing at the source: a signed receipt's
  findings table and its changed-files table named the same file two different
  ways; receipt bytes differed by platform for an identical tree, so a
  cross-platform reproduction could not match; and vendored-directory exclusion
  (`.claude/`, `vendor/`, …) silently stopped matching on Windows, pulling
  tooling payloads back into analysis.
- `changedFindings()` now compares paths separator-agnostically as well. The
  source fix already makes both sides POSIX, so this is defense in depth against
  any future caller that hands in a raw platform path.

## 0.2.35 — 2026-08-07

- **Security analysis now runs locally.** The rule pack and taint solver that
  previously existed only in hosted scans execute on your machine, offline, over
  the JavaScript, TypeScript and TSX in your repository — the same engine, not a
  reimplementation. Seven rules ship: SQL injection tracked from request source
  to query execution, mass assignment, open-record write payloads, un-awaited
  database writes, swallowed errors, coercion-prone `==` comparisons, and N+1
  queries in loops.
- The blocker was packaging, not the rules: the tree-sitter WASM grammars the
  engine parses with are six times the CLI's entire 1 MB release budget. So the
  engine moved behind an injected parser interface and the CLI got a
  zero-dependency JavaScript/TypeScript/JSX parser that emits the same syntax
  vocabulary. One rule pack, two front-ends, nothing duplicated to drift.
- That parser is strict where a normal one recovers: anything it cannot
  represent exactly is skipped and reported as lost coverage, so unsupported
  syntax costs a finding CodeTruss never makes rather than one it makes wrongly.
  Both parsers were run over 1,314 real files with the same rules and produced
  identical findings — nothing found only locally, nothing lost.
- **Local security findings are REVIEW_REQUIRED, never FAILED.** They do not
  fail a verdict or halt an agent turn on their own. Blocking is a promotion
  precision has to earn on real repositories; severity alone does not grant it.
- `unawaited-persistence` now also catches a raw driver write whose promise is
  dropped — `pool.query("INSERT …")` with no `await` — which the ORM-shaped
  checks could not see. Reads, callback-style calls, and handled promises are
  untouched.
- **Receipts state the new boundary.** The analysis profile is now
  `local-registry-v2`, and the receipt names both what the local pass checked and
  what it still did not: command injection, path traversal, SSRF, XSS,
  deserialization, and every non-JavaScript language. Receipts signed by earlier
  versions keep verifying byte-for-byte against the wording they were signed
  with.
- Cost: about 0.3 s over 2.5 MB of source, roughly a quarter of one percent of
  the agent hook's budget, and faster than the hosted parser it stands in for.

## 0.2.34 — 2026-08-07

- Findings can now carry a suggested fix: a description, a unified diff or
  snippet, and a required safety note, rendered in the receipt as a **Suggested
  fixes** section and available as `fix` on the JSON finding. A suggestion is
  never applied, written, or run, and never framed as required — a change derived
  from one matched line cannot see the rest of the codebase.
- An analyzer attaches one only where the finding's own evidence determines a
  single correct change. Where the right fix is ambiguous the prose suggestion
  stays the whole answer and no `fix` is attached, because a wrong autofix is a
  false positive with extra damage.
- **Committed secrets** get a move-to-env diff: the literal becomes
  `process.env.X` (or `os.environ`, `os.Getenv`, `ENV.fetch`, `getenv` by
  language), with the matching `.env.example` line appended at the correct
  offset. The removed line is shown with the credential **masked** — CodeTruss
  never echoes a credential, not even into its own suggestion — so the diff
  cannot apply cleanly by design, and the note says so and leads with rotation.
  A tracked `.env` gets the untracking commands instead. A key inside a call, a
  private-key block, or an unsupported language gets prose only.
- A credential found inside a **generated** file is still reported in full, but
  gets no diff: the next generation would overwrite the edit, so the fix belongs
  in the generator's input, not in that line.
- **No lockfile committed** gets the refresh command for the package manager the
  repository itself declares. With no such evidence it lists every option rather
  than guessing one — a lockfile from the wrong manager is worse than none.
- **Missing README** and **No CI pipeline** get minimal starter blocks. The
  workflow is built only from scripts `package.json` actually defines, and is
  withheld entirely where the setup steps would have to be guessed.
- Under an agent hook, the highest-severity suggestion is appended to the Stop
  summary in its own field, so the five-reason display cap can never drop it and
  the agent can correct the change before a person opens the receipt.
- Suggested fixes quote real source lines, so they are stripped from the hosted
  sync copy. Receipts whose findings carry no fix render byte for byte as before,
  so earlier signatures keep verifying.

## 0.2.33 — 2026-08-07

- A generated-file banner can no longer hide a committed credential. A four-line
  file whose first line read `// AUTO-GENERATED FILE - DO NOT EDIT` produced a
  signed PASS with a live Stripe key on line four; the identical file without
  that comment FAILED. Generated classification exists to stop machine-written
  output producing spurious "oversized file" findings, but it was excluding those
  files from every analyzer, secret scanning included, so one comment bypassed
  the whole scanner. The excluded text is now retained for the secrets pass only:
  LOC totals, the architecture graph, and the quality analyzers keep skipping
  generated files exactly as before.
- Name every excluded file, at any size. The exclusion note used to appear only
  above 500 LOC or 50KB and named just the first file as "e.g." — so a small
  generated stub was dropped from analysis with nothing on the receipt to say so.
  It now lists every excluded path whenever anything is excluded, and reports
  small volumes in bytes rather than rounding them to "0 KB".
- `setup` stops reporting "No repository verification commands were detected"
  when it detected them. An unattended run deliberately withholds commands it has
  no permission to execute; it now prints the list it found, why it withheld it,
  and the exact step that enables it. When detection genuinely fails because no
  lockfile is committed, it says the lockfile is the reason instead of implying
  the repository has no tests.
- npm and yarn repositories get the same `[lint, test]` collection pnpm already
  had, instead of losing their lint command over which lockfile they commit.
- `setup`'s own footprint — `.codetruss.yml`, `.claude/**`, `.codex/**`,
  `.githooks/**` — is in scope by default, so installing CodeTruss no longer
  reports CodeTruss as scope drift on a user's first commit. `.codetruss.yml`
  remains a sensitive policy surface, and setup now says to commit it so the
  policy stays reviewable.
- The installer no longer prints "Ready" while an older binary shadows the one it
  just installed. `install.sh` compares what `command -v codetruss` resolves to
  against the completed install and prints the PATH fix when they differ;
  `hooks doctor` warns on the same version skew, reading the shadowing install's
  manifest rather than executing whatever is first on PATH.
- `codetruss verify-policy trust-key` is listed in `--help`. Blocked-commit
  errors already told people to run it.
- The verification-command trust store honors `XDG_CONFIG_HOME`, matching where
  the saved login already lives. An approval left at the legacy `~/.config` path
  keeps being read, so setting that variable never orphans a trust store.

## 0.2.32 — 2026-08-06

- Infer this turn's scope so a first session reads as signal, not noise. Scope
  drift used to fire the moment an agent touched anything outside the
  directories `setup` happened to find on disk, which made the one detection
  nobody else ships debut as a false alarm. A path with no approved allow root
  can now be classified `inferred` on this turn's own evidence: the task naming
  the path or the feature directory, a cohesive working set under one shared
  parent, or a test file mirroring a source file already in scope.
- Disclose every inferred allowance on the receipt. An "Inferred scope" section
  names each root, what it was read from, and the approved roots it sits beside,
  and the changed-file row reads `allowed (inferred)` rather than `allowed`. The
  PASS reason no longer claims those files were within approved scope. Receipts
  that inferred nothing render byte for byte as before, so receipts signed by
  earlier versions keep verifying.
- Never infer past a hard line. Deny rules win outright, secrets, config and
  dependency surfaces are not inferable, the repository root is never a root,
  and no inferred root may climb above an allow root the repository deliberately
  narrowed. With no allow roots configured at all, the turn is its own scope and
  the receipt says exactly that.
- Keep the mid-turn PostToolUse check quiet about a path inference already
  covers. It sees one tool call, so it infers strictly less than the Stop-time
  receipt and never more.

## 0.2.31 — 2026-08-06

- Capture a baseline for turns that carry no prompt. Harness machine events —
  background-task notifications, hook feedback continuations, and resumed agents
  — reach `UserPromptSubmit` with no prompt at all, and capture assumed there
  always was one. A promptless turn now snapshots tree state like any other turn,
  is labelled honestly, and earns a receipt; previously those turns reached Stop
  with no baseline and went entirely unreviewed.
- `UserPromptSubmit` never blocks. Blocking there erased a person's prompt
  because CodeTruss could not take a snapshot — failing closed against the user
  rather than the agent. Capture failures now emit a note and let the prompt
  through. Stop remains the enforcement point and still fails closed on a turn
  with no provable baseline, so an agent cannot finish unreviewed.
- Exact capture retries a working tree that changes mid-snapshot, bounded at
  three attempts, and the Stop hook timeout moves to 360s. It had been 300s —
  exactly the internal review timeout — so the harness killed the hook at the
  moment the graceful timeout receipt would have been written.
- Shipped alongside, outside the CLI: production deploys now apply database
  migrations before serving new code, which had been running against an old
  schema.

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
