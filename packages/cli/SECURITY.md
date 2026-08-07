# Security policy

## Supported versions

CodeTruss supports the current CLI release. Upgrade before reporting a problem
that may already be fixed:

```bash
curl -fsSL https://codetruss.com/install.sh | sh
codetruss --version
```

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Email
`zack@codetruss.com` with:

- the affected CLI version and operating system;
- a minimal reproduction or evidence;
- the impact you believe is possible; and
- whether public disclosure is time-sensitive.

Do not include repository source, credentials, receipt signing keys, provider
keys, or unredacted diffs unless CodeTruss explicitly asks for a safe transfer
method. Receipt signatures and public signing keys are not secrets.

CodeTruss will acknowledge a valid report within three business days, provide
an initial severity assessment within seven business days, and coordinate a
fix and disclosure timeline with the reporter. Good-faith research that avoids
privacy violations, service disruption, data destruction, and access beyond
what is needed to demonstrate the issue is welcome.

## Grammar packs: what the digest pin covers, and what it does not

`codetruss grammars install python` downloads code that this CLI later executes
in your process. Every artifact is pinned to an exact SHA-256 compiled into the
binary, checked as the bytes arrive and re-checked on every load, and the buffer
that was hashed is the buffer that is executed — nothing is re-opened by path.

That pin protects you against a **compromised download origin**. If codetruss.com
or anything between it and your machine serves different bytes, the install
fails and no Python is analyzed. It is a strong guarantee and it is the one the
pin was built for.

It does **not** protect you against a compromised **build**. The pin, the
published artifact, and the offline check that compares them are all derived
from the same `node_modules` on the machine that cut the release. Anything able
to write there between `pnpm install` and the release command would poison all
three in one move, and every check would still pass. A digest pin can only ever
say "these are the bytes we published"; it cannot say "these are the bytes we
meant to publish".

Two things narrow that window, and neither closes it:

- **`pnpm grammars:attest` (run by the release).** The tarball digest recorded
  in `pnpm-lock.yaml` is checked against what the npm registry serves for that
  exact version, the registry's ECDSA signature over the version/digest pair is
  verified against npm's published keys, the tarball is downloaded and hashed,
  and its files are compared against the `node_modules` copies the pack is cut
  from. A file dropped into `node_modules` fails the release. This runs on the
  release machine, so a compromise deep enough to patch the script is not caught
  by the script.
- **`pnpm grammars:verify` (runs in every build).** Re-derives the whole
  generated pin from the published artifacts and compares it byte for byte, and
  checks that the versions a pack claims are the versions the lockfile pins. It
  is an internal-consistency proof, not an independent one.

There is no reproducible build and no third-party rebuild of these artifacts.
Anyone can check the published bytes for themselves: each artifact is served
with a `.sha256` sidecar under `/downloads/grammars/`, the same digests appear
in the CLI's `src/grammar-pack-manifest.ts`, and the upstream packages
(`web-tree-sitter`, `tree-sitter-wasms`) are copied byte for byte with nothing
recompiled, so a published artifact can be diffed directly against the version
you install yourself.

## Scope

Security-sensitive surfaces include artifact/install integrity, receipt
signature or verification bypasses, false PASS conditions, provider-key or API
credential disclosure, unintended network transmission, path traversal,
command execution outside an approved verification policy, and organization
isolation failures in explicit receipt sync.
