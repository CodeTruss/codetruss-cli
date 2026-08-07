# CodeTruss CLI

The deterministic first-pass verification gate for AI-written code.

An agent finishes a change. Something has to look at it before a human does.
CodeTruss Boundary is that first pass: it captures an exact before/after Git
evidence pair, checks the change against the task contract you declared, runs 15
deterministic analyzers, a local security pass, and your own project checks, then
signs a `PASS`, `REVIEW_REQUIRED`, or `FAILED` receipt you can re-verify later.

Routine changes clear the checks and pass. Material changes escalate for human
sign-off. Every verdict leaves a receipt that records the reasons, and the
receipt also names what never ran.

It is local-first. Nothing is uploaded unless you explicitly run `codetruss sync`.

## Install

Node.js 20.9 or newer. macOS or Linux:

```bash
curl -fsSL https://codetruss.com/install.sh | sh
codetruss setup
```

Homebrew on macOS:

```bash
brew install DeliriumPulse/codetruss/codetruss
```

Windows PowerShell:

```powershell
irm https://codetruss.com/install.ps1 | iex
codetruss setup
```

The shell installers resolve the versioned artifact named in
[`codetruss-cli-latest.json`](https://codetruss.com/downloads/codetruss-cli-latest.json)
and verify its published SHA-256 digest before installing.

To pin an exact version, install the immutable archive directly:

```bash
npm install --global --ignore-scripts --no-audit --no-fund \
  https://codetruss.com/downloads/codetruss-cli-0.2.39.tgz
```

The `@codetruss/cli` package on the npm registry is published as a separate,
manually dispatched step and currently trails the website at `0.2.24`. Use the
installers or the versioned archive above for the current release.

## First run

```bash
codetruss review --task "Review my current agent changes"
codetruss verify latest
```

That first receipt needs no account and no configuration. Without an allow
policy CodeTruss infers the scope of the turn, marks each file that inference
covers `allowed (inferred)`, and discloses on the receipt that it did so, which
keeps a first run readable as signal instead of blanket scope drift. Anything
the inference does not cover is still unexpected.

Run `codetruss setup` once at the Git root to make it automatic. It proposes
conventional source roots rather than repository-wide access, shows any detected
verification commands with their exact trust fingerprint before you trust them,
installs the hooks you pick, and runs diagnostics. It uploads nothing. Codex asks
for one final project-hook approval in `/hooks`.

To wrap an agent so the task and both Git states are captured together:

```bash
codetruss run --task "Fix auth" --allow "src/auth/**" --verify "pnpm test" -- codex exec "Fix auth"
```

## Claude Code, Codex, and Agent Skills

The open integration wrappers teach coding agents to configure and operate the
separately installed CLI. They contain no second analyzer, add no MCP server, and
create no new upload path.

```bash
claude plugin marketplace add DeliriumPulse/codetruss-plugins
claude plugin install codetruss@codetruss
```

```bash
codex plugin marketplace add DeliriumPulse/codetruss-plugins
codex plugin add codetruss@codetruss
```

Agent Skills clients can install the same canonical skill for both agents:

```bash
npx --yes skills add DeliriumPulse/codetruss-plugins \
  --skill codetruss --agent claude-code codex -y
```

See the [skills.sh listing](https://skills.sh/deliriumpulse/codetruss-plugins/codetruss)
or [DeliriumPulse/codetruss-plugins](https://github.com/DeliriumPulse/codetruss-plugins)
for the MIT-licensed manifests, skill instructions, and marketplace source.

## Commands

```text
codetruss run --task "..." [--allow GLOB] [--deny GLOB] [--verify CMD] [--no-verify]
              [--llm] [--provider anthropic|openai|claude] -- <agent-cmd>
codetruss review [--staged] --task "..." [--allow GLOB] [--deny GLOB] [--verify CMD]
                 [--no-verify] [--llm] [--provider anthropic|openai|claude]
codetruss report [id|latest] [--json]
codetruss list [--json]
codetruss metrics [--json]
codetruss setup [--allow GLOB] [--deny GLOB] [--hooks all|pre-commit|claude|codex|none]
                [--trust-verify] [--yes]
codetruss init [--allow GLOB] [--deny GLOB] [--force]
codetruss verify [id|latest]
codetruss sync [id|latest] [--dry-run]
codetruss auth login|status|logout
codetruss verify-policy [status|trust|trust-key|revoke]
codetruss hooks install|status|doctor|uninstall [pre-commit|claude|codex|all]
```

`verify-policy status`, `trust`, and `revoke` govern whether the repository's
detected verification commands are trusted to run. `verify-policy trust-key`
is separate: it appends your local signing key to `signing.publicKeys` so a
teammate can sign receipts as themselves instead of sharing a private key.
Commit `.codetruss.yml` afterward so the rest of the team inherits the change.

## Fail-closed policy

CodeTruss cannot return `PASS` until the approved scope is explicit. Guided setup
requires at least one useful allow glob. Lower-level `codetruss init`
intentionally starts empty unless `--allow` is supplied. Deny rules beat allow
rules, and sensitive surfaces such as CI, infrastructure, migrations, secrets,
dependencies, and lockfiles are flagged independently of scope.

```yaml
# .codetruss.yml
version: 1
allow:
  - src/auth/**
  - test/auth/**
deny:
  - infra/**
  - .github/workflows/**
verify:
  - pnpm lint
  - pnpm test
receipts:
  dir: .codetruss/receipts
llm:
  maxDiffBytes: 200000
```

Command-line `--allow`, `--deny`, and `--verify` supply the policy for a single
run. Repository configuration cannot redirect authenticated sync traffic;
production sync is fixed to `https://codetruss.com`.

## Verdicts and exit codes

| Verdict | Exit | Meaning |
|---|---:|---|
| `PASS` | 0 | No blocking or review signal was found; any configured verification commands passed. |
| `REVIEW_REQUIRED` | 1 | Scope drift, a denied or sensitive surface, dependency changes, uncertain attribution, a medium-or-higher finding, or optional LLM review needs human judgment. |
| `FAILED` | 2 | The agent or a verification command failed, evidence is incomplete, or a high/critical security or dependency finding blocks the result. |

Usage and environment errors exit `3`. A receipt records every explicit reason.
The verdict is not a confidence score.

## What a receipt says, including what it did not check

Receipts are written as Markdown and JSON next to hashed patch evidence, and can
be rechecked later with `codetruss verify latest`. Every receipt states the
detection gaps in its own body, so a `PASS` is never mistaken for a security
clearance. Abridged from a real 0.2.36 run, so it prints the `local-registry-v2`
profile and its thirteen-analyzer wording. A run on this release prints
`local-registry-v3` and fifteen; 0.2.39 keeps the v2 renderer frozen so the
receipt below still verifies byte-for-byte as signed:

```markdown
# CodeTruss receipt — REVIEW_REQUIRED

- **Task:** Fix auth callback validation
- **Evidence trees:** `a2303191…` → `0f481c3c…`
- **Policy SHA-256:** `82db19fe…`

## Verdict: REVIEW_REQUIRED

- 1 file(s) changed outside approved scope: infra/main.tf
- sensitive surfaces changed: infra/main.tf (iac)

## Analysis profile

Profile: `local-registry-v2`.

The 13 deterministic registry analyzers ran locally on this machine, plus a
local security pass: the shared SAST engine — the same rules and the same
source-to-sink taint tracking as the hosted audit — over the JavaScript,
TypeScript and TSX in this repository.

### What the local security pass checked

- **SQL injection (CWE-89).** Untrusted input tracked from request sources
  through string building into query execution.
- **Mass assignment (CWE-915).** A raw request body spread into a database
  write, and write helpers whose payload type accepts arbitrary keys.
- **Un-awaited database writes, swallowed errors, coercion-prone `==`
  comparisons, and N+1 queries in loops** — the defect classes coding agents
  most often introduce.

### What did not run

- **The rest of the security rule pack.** Command injection, code injection,
  path traversal, SSRF, open redirect, XSS and insecure deserialization were
  **not** checked here.
- **Non-JavaScript languages.** The local pass covers JavaScript, TypeScript
  and TSX only.
- **Hosted symbol graph.** No cross-file call or data-flow graph was built.
- **Optional LLM review.** No model read this diff.
- **Hosted Health scores.** Not calculated, reported as **N/A**.

Local security findings are reported for review and do not fail the verdict on
their own.

A PASS verdict means the passes listed above never ran and the passes that did
run found nothing new. It is not a statement that this change is secure.
```

Since 0.2.35 the security rule pack and its taint solver run locally and
offline over JavaScript, TypeScript and TSX — the same engine as the hosted
audit, not a reimplementation. The rest of the rule pack, every other language,
and the symbol graph remain hosted-only, and the receipt names them rather than
leaving their absence to be inferred. Local security findings are
`REVIEW_REQUIRED` at most; they never fail a verdict on their own.

Where a finding's own evidence determines a single correct change, the receipt
also carries a **Suggested fixes** section with a diff and a required safety
note. Nothing is ever applied, written, or run. A committed credential is shown
with its value masked, so that diff cannot apply cleanly by design and the note
leads with rotation.

## Measured accuracy

On a nine-case adversarial corpus of AI-agent bug classes, the analyzers caught
six at the exact file and line, with zero false positives across 177,703 lines
in eight repositories. The three misses are named, each with the reason a rule
that caught it would fire on legitimate code more often than on the bug.

The read-modify-write race was published as a miss and now sits in the caught
half: it moved because the rule shipped, not because the bar moved.

Method, per-case reasoning, and the misses are published at
[codetruss.com/benchmark](https://codetruss.com/benchmark).

## Privacy

`run`, `review`, `report`, `list`, `metrics`, `init`, `setup`, `verify`,
`verify-policy`, and the hook checks are deterministic and run locally without
contacting CodeTruss. Installing fetches release metadata and package bytes from
CodeTruss or npm.

Optional `--llm --provider anthropic|openai|claude` sends the bounded task and
diff straight to that provider using your own API key or authenticated local
Claude Code. It never crosses CodeTruss servers, and it is force-disabled under
agent hooks so hook receipts stay deterministic. The receipt discloses reviewed
versus total diff bytes, and truncation prevents `PASS`.

`codetruss sync` is the only command that uploads a receipt, and it strips the
patch, absolute local path, agent command, raw verification commands and output,
and signing secrets. There is no background telemetry. `auth login`, `status`,
and `logout` contact CodeTruss session endpoints only and send no source, patch,
or receipt.

Agent-turn evidence is held in a private per-turn Git object store under Git
metadata, is invisible to ordinary repository Git commands, and is removed once
the receipt is complete.

`.codetruss.yml` is reviewable repository policy and may be committed.
`.codetruss/` holds local receipts, patches, signatures, snapshots, and generated
hook runners. CodeTruss adds that evidence root to the repository-local Git
exclude and refuses to operate if evidence becomes tracked or is routed through
an unsafe path.

## Pricing

The CLI is free forever. Installing it, running every command above, and
producing signed receipts cost nothing and always will. There is no seat count,
no trial clock, and no feature that stops working once you depend on it.

The paid line sits at the network boundary: local stays free, hosted is billed.
The hosted side starts free, then receipt History at $9/mo, Pro at $19 per seat,
Team at $15 per seat with a 5-seat minimum, and Agency at $249/mo including 15
client workspaces. See [codetruss.com/pricing](https://codetruss.com/pricing).

## Source and development

This repository mirrors the released CLI and its DB-free analyzer engine. The
published archive contains one bundled executable with no runtime npm
dependencies.

```bash
corepack enable
corepack prepare pnpm@10.28.2 --activate
pnpm install --frozen-lockfile
pnpm validate
```

`pnpm validate` typechecks, builds the deterministic release, runs the source and
adversarial release tests, verifies the result byte-for-byte against the exact
published website artifact recorded in `release-reference.json`, and exercises a
clean global install.

Verify a downloaded release yourself:

```bash
gh attestation verify codetruss-cli-0.2.39.tgz --repo DeliriumPulse/codetruss-cli
shasum -a 256 -c codetruss-cli-0.2.39.tgz.sha256
```

Maintainers should follow [docs/RELEASE.md](docs/RELEASE.md). Tag-driven GitHub
releases and attestations do not depend on npm credentials; npm publication is a
separate, explicitly confirmed workflow that sends the already-attested bytes.

## License and support

CodeTruss-authored source is source-visible proprietary software, not open
source. See [LICENSE](LICENSE) before using or copying it. Bundled dependencies
retain the licenses in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating. Report security
problems privately under [SECURITY.md](SECURITY.md). Product documentation and
downloads are at [codetruss.com/cli](https://codetruss.com/cli).
