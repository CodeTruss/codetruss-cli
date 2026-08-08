# Changelog

CodeTruss CLI follows semantic versioning. Release artifacts and their SHA-256
checksums are published at <https://codetruss.com/downloads/codetruss-cli-latest.json>.

The current public release is [v0.2.51 on GitHub](https://github.com/CodeTruss/codetruss-cli/releases/tag/v0.2.51),
distributed from <https://codetruss.com/downloads/codetruss-cli-latest.json>.
The npm `latest` tag is still
[`@codetruss/cli@0.2.50`](https://www.npmjs.com/package/@codetruss/cli/v/0.2.50):
npm publication is a separate, manually dispatched step, so npm can trail the
website and the GitHub release.
Entries explicitly marked `(unpublished)` are retained release candidates that
were superseded before distribution.

## Unreleased

No unreleased changes.

## 0.2.51 — 2026-08-08

- **A file CodeTruss could not parse reported the user's change as FAILED.** On
  `sindresorhus/ky`, a one-line comment change returned `FAILED`, exit 2, for a
  reason that named no file: `1 file(s) could not be parsed locally`. The
  trigger was a `unique symbol` declaration — standard TypeScript since 2018 —
  in `source/utils/merge.ts`, which the bundled zero-dependency grammar cannot
  read. Reproduced identically on `honojs/hono` and `colinhacks/zod`. Because
  `codetruss setup` installs a pre-commit hook, FAILED also blocked the next
  `git commit`, with uninstalling as the only escape.

  Our inability to read a file is our limitation, not a defect in the change.
  Every entry that reaches the verdict as an evidence issue is now classified at
  the point where its cause is still known, rather than by matching on message
  text at the verdict:

  - **`missing` — no evidence at all — still FAILS.** No required analyzer pass
    ran; the index did not report coverage. Nothing can be concluded from a run
    like that in either direction, so the receipt refuses rather than reporting
    a verdict it has no basis for.
  - **`partial` — a hole in evidence that otherwise exists — is now
    `REVIEW_REQUIRED`.** A file the parser could not read, a file too large to
    load, an unreadable file, the file-walk bound, a wall-clock ceiling, a
    truncated diff capture. None of these is a statement about the change; each
    is a limit of this tool. They withhold PASS, are named on the receipt, and
    exit 1 — which the pre-commit hook allows.

- **Coverage gaps now name their files.** The engine recorded that *n* files
  could not be parsed and dropped which ones before the receipt was signed. A
  count with no path is unactionable — a reader is told something in their
  repository is unreadable and given no way to find it. Parse failures and
  in-file scan errors are now carried as bounded path lists through the scan
  diagnostics, disclosed in the pass detail (so they reach the terminal), and
  recorded in the signed pass metrics alongside `degradedLanguages` (so a later
  reader recovers them without re-parsing an English sentence).

- **New `exclude` key in `.codetruss.yml`.** Globs listed there keep their files
  out of the analysis index entirely, so a file this tool cannot read need not
  sit on every receipt forever. It is an analysis exclusion only: an excluded
  path is still inventoried as a changed file, still classified against scope,
  and is named — with its glob and its matched paths — in the receipt's coverage
  notes. It also enters the policy fingerprint, because what a repository chose
  not to have analyzed is part of its policy. An exclusion that hid itself would
  be a worse bug than the coverage gap it works around.

- **One design asset no longer forces REVIEW_REQUIRED forever.** A `logo.ai`
  committed with a text-ish extension made every change to that repository
  REVIEW_REQUIRED, permanently, via `apparent text file(s) contained binary
  data`. That contradicted the same file's own arithmetic: binary-in-text files
  are already subtracted from the coverage denominator as unanalyzable, so the
  ratio said nothing was lost while the verdict said coverage was partial. It is
  now disclosed as a classification note on the receipt and does not gate the
  verdict.

- **A commented-out regex ran the analyzer phase past seven minutes at 100%
  CPU.** `colinhacks/zod` never finished a review. The cause was not the parser:
  the literal-stripping expression shared by the `complexity` and `comment-slop`
  analyzers spelled its escape handling as `(?:\\.|(?!\1).)*`, which lets a
  backslash be consumed by either branch. On an unterminated literal the engine
  then tries every partition of the backslashes in it. `packages/zod/src/v3/
  types.ts:607` is a commented-out email regex with 133 backslashes and no
  closing quote: 2^133 on one 928-character line. It outlived both advertised
  wall-clock ceilings because those bound the SAST pass and this runs in the
  registry analyzers. Excluding the backslash from the second branch makes the
  alternatives disjoint; the same line now completes in under a millisecond with
  byte-identical output, and the fixture is pinned in the test suite.

## 0.2.50 — 2026-08-08

- **`dead-code` spent 26 of this analysis's 27 seconds and bought nothing with
  them.** The pass concatenated every indexed JS/TS file into a single string —
  18.2 MB on `calcom/cal.com` — and then ran one regular expression per
  candidate module against the whole of it. That is O(candidates × corpus
  bytes): 1,500 sweeps of an 18 MB string, roughly 64 GB of scanning, to decide
  1,500 yes/no questions. And it bought nothing, because the pass has been
  saturated at its 20-finding output cap the entire time — more scanning changed
  only *which* candidates were examined, never how many findings came out. It
  now reads the corpus twice, building one index of the filename stems the
  repository actually references, and answers each candidate with a set lookup.
  On `calcom/cal.com@b2c28a23` (7,691 files, 517,420 LOC) `dead-code` drops from
  25.8s to 0.03s and the whole deterministic analyzer phase from 27.3s to 1.5s.

  **The findings are unchanged, and that was checked rather than assumed.** The
  old expression matched a filename stem wherever it appeared — inside strings,
  inside comments, inside unrelated tokens — and a tidier index that quietly
  stopped doing so would start reporting live modules as dead. So the
  replacement reproduces that looseness exactly. On four pinned repositories
  (cal.com, astro, TanStack/query, hono) the reported findings, the findings
  withheld behind the cap, the completeness flags and the pass metrics are
  byte-identical before and after, and a differential run against the original
  expression agrees on all 60,600 generated cases. A stem containing whitespace
  or a quote character can still straddle the delimiters the index keys on, so
  those candidates keep the original whole-corpus test; no real filename needs
  it, and the fallback exists so the rewrite cannot narrow the rule by accident.

## 0.2.49 — 2026-08-08

- **A redirect to a path this codebase wrote itself was reported as an open
  redirect, and on one real repository seventeen of nineteen such reports were
  false.** 0.2.45 widened the open-redirect sink to JSX `href`/`action`,
  `location.assign|replace|href` and `router.push|replace`, and that widening
  was narrowed against this repository alone. An open redirect requires the
  attacker to control the ORIGIN — the host, or the leading `//` or scheme that
  decides it — and two shapes cannot reach it. `new URL(reference, base)`
  resolves by WHATWG rules, so any reference that is not itself absolute takes
  the base's origin and the origin question collapses onto the first argument;
  the head-position analysis that already answers exactly that question for a
  template or a concatenation now re-asks itself there instead of treating the
  construction as opaque. `new URLSearchParams({ … })` is a query-string
  builder whose serialization is `application/x-www-form-urlencoded`, so `/`,
  `:`, `<`, `&`, `=`, `?` and `#` all come back percent-encoded and a value put
  in this way can only ever emerge as an encoded query value. On `calcom/cal.com`
  the open-redirect count falls from 19 to 12, on `vercel/commerce` from 1 to 0,
  on `shadcn-ui/taxonomy` from 1 to 0, and six further SaaS repositories produce
  byte-identical findings before and after.

  What still fires, deliberately: `new URL(req.query.next, req.url)`, because a
  bare reference may be absolute and override the base; a protocol-relative
  reference, which discards the base origin; `new URL(x)` with one argument,
  where `x` is the whole URL; and `new URLSearchParams(location.search)`, which
  PARSES rather than builds, so reading a value back out of it keeps its taint.
  Writing a tainted value into a query string is safe; reading one out and using
  it as the target is the vulnerability, and that direction is unchanged.

  Recall cost, stated plainly: a redirect whose reference begins with a literal
  `/` is no longer reported however tainted the rest of it is, which takes
  `new URL('/fixed', attackerControlledBase)` host injection with it — the same
  trade-off `evalOrigins` already documented for the constant case. Neither
  suppression can be reached through a local variable, so
  ``const u = `/x/${t}`; res.redirect(u)`` is still reported.

## 0.2.48 — 2026-08-07

- **Ten bounded passes said "truncated" without ever learning what they were
  truncated out of, so the largest repositories got no score at all.** A
  required pass that stopped early is not authoritative, and the only way back
  is to show it still covered enough of its input. An output cap could never
  show that: it stops at N and never counts past N, so no denominator exists and
  the gate has to assume the worst. On a 7,690-file, 517k-LOC repository ten
  required passes tripped a cap — acquisition, the symbol graph, the knowledge
  graph, and the duplication, secrets, dead-code, complexity, vulnerabilities,
  comment-slop and speculative-structure analyzers — and all five score axes
  were withheld. Nobody decided that; it fell out of the arithmetic, and it got
  more certain the bigger the repository was.

  Every one of those caps now reports what it cost, in the unit it bounds.
  Candidate-file bounds (duplication, dead-code, complexity, comment-slop,
  speculative structure) divide the files they examined by the files the filter
  produced — both numbers already existed, one slice apart. The secret scan and
  the TODO scan keep counting after they stop collecting, so they report matches
  shown over matches found. The vulnerability pass reports manifests read over
  manifests present, and package versions checked over package versions
  declared, whichever is worse. Acquisition divides the archive entries it wrote
  by the entries it saw. The symbol graph reports files parsed over candidate
  files and call sites kept over call sites found; the knowledge graph counts
  the distinct nodes and edges its caps refuse, so those have denominators too.

  What this is not: a way to publish a score that should be withheld. The
  threshold is unchanged at 95%, no pass gained a path around it, and a cap that
  still cannot name its denominator still claims nothing and still voids the
  score. The change is that a pass which CAN name it now does, so the existing
  gate can tell one oversized archive entry in 7,690 apart from an analyzer that
  lost half its findings. A repository whose secret scan reported 500 of 5,000
  matches is withheld exactly as it was before — and now says so in those words.

- **`vulnerabilities` withheld every score with a reason that said nothing had
  been lost.** The pass truncated on the dependency-manifest bound and then
  reported package-version coverage, which was complete: "covered 181 of 181
  package versions", printed as the justification for publishing no score at
  all. Two independent bounds share that pass, and only one of them was ever
  described. Each bound that bites is now named in its own unit — "read 5 of 92
  dependency manifests", "checked 200 of 400 declared package versions" — and
  the coverage claimed is the worst of them.

- The secret scan's reported coverage is the fraction of MATCHES shown rather
  than the fraction of files read, superseding the file-fraction measure added
  in 0.2.47. Both answer "how much did the cap cost", but only the match count
  answers it in findings: the file measure reads 100% whenever the cap is
  reached on the last file scanned, and 2% when it is reached on the first,
  neither of which is the number of credentials a reader cannot see. The sweep
  no longer stops at the cap, which costs one more pass over a tree the scanner
  already sweeps in full whenever the cap is not reached.

- The TODO pass counted markers only up to its 500-marker retention bound, so
  its headline finding — a count — reported the bound instead of the codebase on
  any repository above it. The count is now exact; the bound governs only which
  markers get individual findings.

## 0.2.47 — 2026-08-07

- **A loop variable named `event` was treated as an HTTP request.** The taint
  engine decided an expression was untrusted input by looking at the NAME of the
  root identifier: `event`, `args`, `context`, `params` and `ctx` were on the
  request-root list alongside `req` and the PHP superglobals, and nothing
  checked that a parameter had actually bound the name. In a 517k-LOC codebase
  we scanned, `for (const event of salesforceEvents)` made every
  `event.<anything>` a source, and the three CRITICAL SQL-injection reports that
  came out of that one loop were 39% of the repository's entire security
  deduction. The rows were already inside the database they were said to be
  injecting into. Those five ambiguous roots now count as a request only when
  the enclosing function's signature bound them, positionally or by
  destructuring (`({ ctx, input })` is how most handlers are written, so the
  gate sees through patterns). The unambiguous roots are untouched: nobody names
  a loop variable `req` or `$_GET`.

  The narrowing is real and we are not hiding it. A handler that lands its
  request in a LOCAL named `event` — `const event = JSON.parse(body)` — or a
  serverless adapter that binds it through a module-level variable now loses the
  source, and every finding that depended on it. The one shape that mattered in
  practice, `const params = useSearchParams()`, is covered again by treating
  `useSearchParams()` and `useParams()` as sources in their own right: the call
  is evidence, the variable's name never was.

- **Placeholder detection could bless a real key, and did it silently.** Two
  compounding defects. The words that mark a value as fake were matched anywhere
  inside it, so `xxx` occurring by chance inside a random credential silenced
  the line — measured against 400 real `generateKeyPairSync` RSA-2048 keys, 18
  of them (4.5%) contain a matching run. And the check ran against the whole
  regex match rather than the value, so `examplePassword = "<real secret>"` was
  dismissed because of the identifier next to it. Every alternative is now
  anchored to a token boundary, the pre-existing ones included, and the subject
  is the extracted quoted value. Private key blocks are excluded from
  value-level matching entirely — a base64 PEM body is a high-entropy blob, not
  a string that can announce itself as fake — so the 4.5% collision cannot reach
  the "No action needed." path by another route. The same 400 keys now produce
  zero matches. `mock`, `stub`, `test-key`/`test-secret` and `not-a-real` join
  the list as genuine placeholder forms.

  Consequence worth knowing before you upgrade: a credential-shaped string that
  merely CONTAINS a word like `fake` inside its random body is no longer
  downgraded to INFO. `sk_live_51QxR8fake2eKjL9…` is indistinguishable from a
  live key by any rule that does not simply trust a substring, so it is reported
  rather than blessed. Announce a placeholder with delimiters
  (`sk_live_test-key-…`, `not-a-real-password`) and it is recognised as before.

- **A placeholder declared one line up was invisible.** The placeholder check
  read a single line, so a Swagger `@ApiProperty({ example: { … } })` two lines
  above a documentation sample did not cover it and the sample was reported as a
  committed leak. A placeholder marker that opens a block now covers that block,
  which ends at the first non-blank line indented no further than the opener.

- **Findings were double-charged, and repeats were charged in full.** Scoring
  summed severity weights flat. Eight firings of one rule against one mock
  string in one spec file cost eight findings — 14% of one repository's security
  deduction for a single review decision — and a hard-coded credential found by
  both the secrets analyzer and the SAST rule was charged twice for one line.
  Repeat hits of the same rule in the same file now decay to `1 + ln(n)`, with
  the worst finding in the group still charged in full, and `(filePath, line)`
  is deduped across analyzers. The finding LIST is unchanged — both entries
  still appear, with their own evidence and their own fix; only the arithmetic
  collapses them.

  The cost lands on concentration: a file with twelve DISTINCT injection sinks
  now prices close to a file with one, and two genuinely different defects on
  one line price as one. Concentration is legitimate signal and most of it is
  lost from the score. It remains visible in the findings.

- **The secret scan stopped at 50 matches and took every score down with it.**
  50 was reached exactly on a 517k-LOC repository, which made every count anyone
  quoted a truncated prefix — and because a truncated required pass is not
  authoritative, a benign cap withheld all five score axes. The cap is now 500,
  and the pass reports the fraction of its eligible files it actually read, so
  an immaterial cap no longer voids the scores while a real coverage loss still
  does.

- Known, unchanged: the `Private key block` pattern matches only the PEM header,
  so anything that inspects the matched text sees `-----BEGIN PRIVATE KEY-----`
  and never the body. That is why the exclusion above is written by credential
  type rather than by trusting the value check to hold over 1,700 random
  characters.

## 0.2.46 — 2026-08-07

- **A repository's own scope globs could crash the review that reads them.**
  `--allow` and `--deny` are matched with `minimatch`, which expands brace
  groups through `brace-expansion`, and the bundled copy was 5.0.7. That version
  bounds the *number* of expansions at 100,000 but not their *length*, so a
  pattern like `{a,b}` repeated a few hundred times keeps the count under the
  cap while making every result as long as the pattern has groups. The arrays
  built while combining them exhaust the heap and abort the process
  (CVE-2026-14257, and the incomplete fix for it). This is reachable here
  because `allow` and `deny` are read from the scanned repository's
  `.codetruss.yml` and validated only as non-empty strings: on 0.2.45's shipped
  bundle, a 7.5 KB glob in that file ends `codetruss review` with an uncatchable
  out-of-memory abort rather than a verdict. `brace-expansion` moves to 5.0.9,
  which bounds the intermediate arrays as well, and the same input now returns a
  verdict. Scope matching is otherwise unchanged.

  What this is not: nothing is disclosed, nothing is altered, and no verdict
  changes. A pattern cannot reach the matcher from a diff, a filename, or the
  network — only from flags you typed or a config file in the tree you pointed
  the CLI at. The worst outcome was a local tool dying instead of reporting.

- **Dependency floors that were pinned to vulnerable versions have been
  raised.** `minimatch` moves to 10.2.6, whose own `^5.0.8` requirement means
  `brace-expansion` can no longer resolve below the patched line. `postcss` was
  held at 8.5.16 by a workspace override added as a security pin months ago and
  never refreshed; it moves to 8.5.26, which carries `nanoid` 3.3.18 with it.
  Neither `postcss` nor `nanoid` is in the shipped bundle — they reach the
  repository only through the test runner — so this changes nothing you install.

## 0.2.45 — 2026-08-07

- **A PASS was reachable by typing.** `codetruss-ignore: <reason>` exists so a
  developer can dismiss a finding beside the code it is about, and the one
  promise it makes is that "nothing was found" can never be reached by editing
  text. It could be. A dismissed finding stops gating the verdict — that is what
  dismissing is for — and the marker was honored wherever those characters
  appeared on the finding's own line, including inside a string literal. A
  minified bundle is one physical line, so a single planted string dismissed
  every credential finding in the file, and the verdict followed. The marker is
  now read only where a person could have written it. It must sit in a COMMENT,
  decided by the same classifier the comment analyzers ship, which separates
  comments from code and from strings; in a language that classifier does not
  cover, the marker is honored only in the placement that needs no classifier —
  a line whose every preceding character is whitespace or comment punctuation.
  Markers are no longer read out of generated, vendored or minified content at
  all: that text had no author who could have meant it. And the reason itself is
  now redacted against the credential patterns before it is quoted. A reason runs
  to the end of its line, so a marker written just before a connection string
  harvested the password verbatim onto a signed receipt and synced it to the
  hosted database — the secret scanner's promise that values never leave it now
  holds for the text other passes copy out of the repository too.

- **Oversized-file findings counted comments as code.** The size analyzer
  measured non-blank lines and then printed the number as a fact: "parser.ts has
  2202 lines of code", in a document a customer can disprove with `wc`. Two of
  this repository's own HIGH findings existed only because of it — the same two
  files measure 1995 and 1996 lines of code, both below the threshold that made
  them HIGH — and the overcount inflated every oversized finding, because the
  800-line gate read the same number. Both the gate and the printed number now
  come from the classifier. Nothing stops being reported that a refactor would
  have helped: a file with 800 lines of code has 800 lines of code however they
  are counted. What stops is documentation manufacturing severity.

- **Redirects that are not redirect calls are now findings.** The open-redirect
  rule matched two method names, `redirect` and `sendRedirect`. Most navigation
  in a React or Next.js codebase is neither: it is `<Link href={returnTo}>`,
  `<form action={next}>`, `location.href = next`, `location.assign(...)` or
  `router.push(...)`, and none of those is a call to anything the rule was
  looking for. It missed a live open redirect in our own repository on that
  basis. Those shapes are sinks now. The call forms are gated on their receiver,
  because `push` and `replace` unqualified are `Array.prototype.push` and
  `String.prototype.replace`; the binding forms fire only where the untrusted
  value IS the navigation target — a value, or a field of the request itself —
  because reading taint off a record that a route segment merely looked up turns
  every call-to-action on a `[slug]` page into an open redirect. Measured against
  this repository, the narrow rule adds the real defect plus two links a reviewer
  should confirm; the wide one added five more that no reviewer should have to.

## 0.2.44 — 2026-08-07

- **The person you hand a receipt to can now check it.** Until this release a
  receipt could only be verified by the repository that produced it: `codetruss
  verify` measures a receipt against the signing keys the local `.codetruss.yml`
  pins, so the client, auditor, or acquirer the evidence was written for got
  `receipt signer <fp> does not match trusted key <fp>` and stopped there. That
  is most of the point of handing someone a receipt, and it did not work. The
  gap was concrete rather than theoretical: publishing one of our own receipts
  publicly required shipping a bespoke standalone verifier alongside it, because
  the CLI would not check another install's receipt. `codetruss verify-receipt
  <receipt.json|dir>` is the supported path. It needs nothing but the files —
  no checkout, no account, no configuration — and it reports two claims
  separately, because they are two different facts and merging them would be a
  lie. **Integrity** is that these bytes have not changed since they were
  signed; it is established from the receipt alone, by checking the signature
  under the key the receipt carries, reproducing the Markdown byte-for-byte from
  the signed JSON, and matching the recorded digests. **Provenance** is that a
  party you trust signed them, and it is established only against a
  `--public-key` you obtained from that party some other way. A receipt vouching
  for its own key proves nothing about who wrote it — forging one takes a
  keypair and a minute — so a run without a supplied key can never print a
  verified result or exit 0. That ceiling is the feature, not a missing half of
  one. The exit codes carry the distinction into scripts: 0 for both claims, 1
  for bytes that are intact but unattributed, 2 for bytes that are not what was
  signed. When integrity fails, provenance is not evaluated at all and says so,
  rather than printing a key match over altered bytes. Evidence a publisher
  withheld — usually the patch, the only part of a receipt that quotes source —
  is reported as unchecked next to the digest the signature does cover, and the
  integrity line names the hole instead of reading clean. `codetruss verify` is
  unchanged and still requires a trusted key; its refusal now names the command
  that can check a foreign receipt instead of dead-ending. Both paths run one
  shared check list against one shared set of accepted Markdown renderings, so
  neither can drift into checking less than it claims, and every superseded
  profile wording stays reproducible, so receipts signed by older releases keep
  verifying byte-for-byte.

## 0.2.43 — 2026-08-07

- **A release can no longer reach you carrying code that does not compile.**
  Three type errors shipped in 0.2.42 and stopped the following release at its
  first build step. The errors were trivial in themselves: a finding category
  that does not exist, and a test helper that was not updated when one of the
  fields it passes became required. Why they shipped is the part worth fixing.
  The CLI's test sources were compiled by no gate upstream of the release job —
  linting does not typecheck, the website build typechecks the website, and the
  test run cannot stand in for either, because esbuild strips types without ever
  checking them. A suite reports 12 of 12 passing with a type error sitting in
  the file it just ran. The release job was the first step in the chain to
  compile those files, which meant a failed build was the earliest available
  symptom, and it arrived only once a version was already a release candidate. A
  `typecheck` gate now runs that same compiler over those same files ahead of the
  tests, in both the local gate and continuous integration, so this class of
  defect surfaces at the edit that causes it instead of at the release it blocks.

## 0.2.42 — 2026-08-07

- **A security scan that could have run for hours now finishes in seconds.**
  Naming the callee of a chained call went the long way round, through a helper
  that eagerly re-derived that same name twice more — so a left-deep method chain
  cost 3^links to analyze. Eighteen chained `.replace()` calls in a single 19 KB
  file extrapolated to roughly 2.1 hours, and a thirteen-link chain took
  30,839 ms; that chain now takes 2 ms. Only the number of times the name is
  computed changed, never the answer. Two wall-clock ceilings back that up —
  five seconds for one file, five minutes for a whole pass — so no future shape
  can hang a scan instead of finishing it. A ceiling that fires is disclosed
  rather than absorbed: the receipt names the files it cut and says plainly that
  the rules which had not run there reported nothing, which is not the same as
  finding nothing.
- **A finding in a file your change never touched is no longer reported as one
  your change introduced.** Analyzers cap how many findings they report. Resolve
  two and two cap slots free up, so findings that had merely been hidden in
  untouched files entered the reported list for the first time — where the
  baseline comparison called them introduced, and a signed receipt then asserted
  that a change broke code its author never opened. The mirror image was just as
  wrong: a finding pushed below the cap read as resolved when nothing had fixed
  it. The comparison now runs over everything each pass found rather than only
  what it reported, while the cap still decides what a receipt shows. The new
  time ceilings above can hide a finding the same way, and that door is shut
  too — but by the opposite means, because a capped finding was found and then
  dropped whereas a file the clock cut was never analyzed at all. There is
  nothing to recover in that case, so a file either the baseline or the final
  could not finish is dropped from both sides, and the comparison makes no claim
  about it in either direction.
- **A verification that passed is no longer reported as timed out because
  something it started outlived it.** On Windows a descendant that escapes the
  process tree keeps the inherited output pipes open, and CodeTruss waited on
  those pipes — so a suite that passed in ten seconds and left a watcher behind
  burned its entire deadline and produced exit code 124 on a signed receipt. A
  local review provider lost finished reviews the same way. Capture now settles
  two seconds after the command's own process exits, on the status the command
  actually produced, and the escape is named in the output instead of being
  absorbed silently. That grace is only ever paid when something really did
  escape. What Windows still does not allow CodeTruss to reap, and what closing
  it would cost, is stated in the code at the point the choice is made.
- **CodeTruss no longer reads its own receipts back in as your source code.** A
  receipt `.patch` is the captured session diff — the full text of every changed
  line — and it classified as source, so the tool analyzed its own audit trail.
  Against this repository's real 156-receipt store that produced 52 spurious
  findings, including duplication findings over receipts that repeat each other
  by construction; those consumed the per-analyzer finding budgets and crowded
  genuine findings out of the report entirely. It also ran the other way: an
  identifier appearing anywhere in a receipt looked referenced, so "exported with
  no consumer" findings silently vanished and returned depending on what the last
  session happened to touch. A repository holding receipts now yields the same
  findings as the same tree with no receipts in it at all.

## 0.2.41 — 2026-08-07

- **You can dismiss a finding you have judged wrong, in the place the judgement
  belongs.** A `codetruss-ignore: <reason>` comment on a finding's own line, or
  on a comment-only line directly above it, marks that finding as dismissed. A
  marker trailing a line of code governs only that line, so it can never reach a
  neighbouring finding its author never looked at. **A dismissal never deletes
  anything.** The finding, its location, and the exact reason its author gave
  all survive into the signed receipt under a "Suppressed findings" heading, and
  the reader decides whether the reason is good — a receipt whose evidence could
  be erased by editing a comment would not be evidence, and "nothing was found"
  must never be reachable that way. The reason is mandatory for the same reason:
  the reason *is* the output, and "someone decided this was fine" is not
  evidence. A bare `codetruss-ignore` therefore dismisses nothing and is
  reported by location, so a developer who wrote one finds out why it did
  nothing. Receipts that dismissed nothing are unchanged, byte for byte.
- **Python SQL injection is now caught through a cursor held in a local.**
  `cur = conn.cursor()` then `cur.execute(f"... {user_input}")` — the canonical
  psycopg/sqlite3/MySQLdb two-step — was invisible, because the sink test was
  lexical and `cur` does not read as a database receiver. The receiver is now
  resolved to its binding, so a name bound to a `.cursor()` call counts however
  it is spelled, including `with conn.cursor() as cur:`. `executemany` joins
  `execute`; `exec` stays name-gated, since a bare `.exec()` is far more often
  `RegExp.prototype.exec` than SQL. Generic receiver names were not loosened, so
  nothing else lost precision.
- **A stalled grammar-pack download now fails with a sentence instead of
  hanging.** `codetruss grammars install` is a foreground command someone is
  watching, and `fetch` will wait out a server that writes one byte and holds
  the socket open forever. Two clocks bound it — a whole-transfer budget and an
  idle budget — and the reason it was abandoned survives into the error, rather
  than the bare "This operation was aborted" an abort produces on its own. Both
  are generous enough that a slow connection is never mistaken for a hostile
  origin.
- **A grammar pack's artifacts are bound by role, not by name prefix.** The
  loader picked the first file whose name started with `tree-sitter-`, so a pack
  carrying an extra artifact ordered ahead of the real grammar would have had
  the extra one loaded — and the pin verifier, which only proved each digest
  appeared somewhere, would not have caught it. Each role must now be filled by
  exactly one pinned artifact; an ambiguous pack does not resolve at all. A pack
  that fails this reports a runtime failure rather than a digest failure, so a
  defect in the CLI's own pin never publishes a receipt accusing the user's
  install of tampering.
- **`SECURITY.md` now states what the grammar-pack digest pin does not cover.**
  The pin protects against a compromised download origin, which is what it was
  built for. It cannot protect against a compromised build: the pin, the
  published artifact, and the offline check that compares them all derive from
  the same `node_modules` on the release machine. `pnpm grammars:attest` narrows
  that window — it checks the lockfile digest against the npm registry, verifies
  the registry's signature, and compares the downloaded tarball against the
  files the pack is cut from — and the document says plainly that it does not
  close it.
- **`hooks doctor` names which fields drifted and what to run.** It reported
  only that an installed handler "differs", which reads identically for a config
  installed several versions ago and a deliberate hand-edit, and named no
  remedy. It now lists the drifted field names — enough to diagnose, without
  putting handler command text in the message — and names the reinstall command.
  This repository's own committed `.codex/hooks.json` was the config that
  exposed it: several versions stale, missing `core.longpaths=true` and pinned
  to the old Stop timeout. It has been refreshed, and a test now compares the
  committed hook configuration against what the installer actually writes, so it
  cannot drift again unnoticed.
- **Build attestation is verified against the CodeTruss organisation.** The CLI
  repository moved from the `DeliriumPulse` account, and every release still in
  circulation has been re-attested under the organisation, so one command
  verifies all of them: `gh attestation verify <artifact> --repo
  CodeTruss/codetruss-cli`. The transferred `--repo DeliriumPulse/…` slug
  returns HTTP 404 and is no longer advertised anywhere. The published manifest,
  the verifier, and the verifier's own tests now derive that command from a
  single module rather than each restating it; the Homebrew tap, plugin
  marketplace and support links follow the organisation too.
- **Internal: `hooks.ts` is now seven modules behind an unchanged public
  surface.** Installation, uninstallation, the doctor, the pre-commit block, the
  agent handler shapes, the agent runner and executable resolution each have
  their own file. No behaviour changed, and the hook tests are unmodified by
  design — an unchanged test suite passing over a moved implementation is the
  evidence that the move was only a move.

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
