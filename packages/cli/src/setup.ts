import type { Dirent } from 'node:fs'
import { access, lstat, readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'
import { createInterface } from 'node:readline/promises'
import type { Readable, Writable } from 'node:stream'
import { CONFIG_FILE, detectVerifyCommands, initialize, loadConfig, type VerifyDetection } from './config.js'
import { inspectHookDoctor, installHooks } from './hooks.js'
import { ensureLocalEvidenceProtected } from './local-evidence.js'
import { trustVerifyCommands, verifyCommandTrustStatus } from './verify-trust.js'

const SUGGESTED_SCOPE_DIRECTORIES = [
  'src',
  'app',
  'apps',
  'packages',
  'lib',
  'components',
  'server',
  'client',
  'public',
  'test',
  'tests',
  'e2e',
  'spec',
  'docs',
] as const

const HOOK_TARGETS = ['all', 'pre-commit', 'claude', 'codex', 'none'] as const
type SetupHookTarget = typeof HOOK_TARGETS[number]

/**
 * The files setup itself writes. Left out of the allow list, setup's own
 * footprint made every user's FIRST commit REVIEW_REQUIRED for "changed outside
 * approved scope" — CodeTruss flagging CodeTruss, on the one run where the tool
 * has to earn trust. These paths are in scope by default; `.codetruss.yml`
 * remains a sensitive policy surface, which is the point of reviewing it.
 */
export const SETUP_FOOTPRINT_GLOBS = ['.codetruss.yml', '.claude/**', '.codex/**', '.githooks/**'] as const

export interface GuidedSetupOptions {
  allow?: string[]
  deny?: string[]
  hooks?: string
  trustVerify?: boolean
  yes?: boolean
  input?: Readable
  output?: Writable
  ask?: (question: string) => Promise<string>
}

function normalizeGlobs(values: string[] | undefined, label: string): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.map((value) => value.trim())
  if (normalized.some((value) => !value)) throw new Error(`setup ${label} globs must be non-empty strings`)
  return normalized
}

function parsePromptGlobs(value: string): string[] {
  return value.split(',').map((glob) => glob.trim()).filter(Boolean)
}

function repositoryWide(glob: string): boolean {
  return new Set(['*', '**', '**/*', './**', './**/*']).has(glob.trim())
}

function hookTarget(value: string | undefined): SetupHookTarget | undefined {
  if (value === undefined) return undefined
  if (!HOOK_TARGETS.includes(value as SetupHookTarget)) {
    throw new Error(`unknown setup hook target ${value}; expected ${HOOK_TARGETS.join(', ')}`)
  }
  return value as SetupHookTarget
}

async function exists(path: string): Promise<boolean> {
  return access(path).then(() => true, () => false)
}

/** Build/output directories a shallow scan must never suggest as change roots. */
const SCAN_EXCLUDED_DIRECTORIES = new Set([
  'node_modules', 'dist', 'build', 'out', 'coverage', 'vendor', 'tmp', 'target', '.git',
])

/** Manifest files whose presence marks a directory as a nested project root. */
const PROJECT_ROOT_MANIFESTS = ['package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml'] as const

async function safeDirectory(path: string): Promise<boolean> {
  try {
    const metadata = await lstat(path)
    return metadata.isDirectory() && !metadata.isSymbolicLink()
  } catch {
    // Missing or unreadable either way: a directory setup cannot even stat
    // must not be suggested, and must not abort the whole suggestion pass.
    return false
  }
}

/**
 * Directory names the repository's own workspace manifests declare as project
 * roots. Read, never guessed: `workspaces` in package.json and `packages:` in
 * pnpm-workspace.yaml name exactly the roots the maintainer means. Only the
 * literal prefix of each pattern is used, and only if it exists on disk.
 */
async function workspaceDeclaredRoots(root: string): Promise<string[]> {
  const patterns: string[] = []
  try {
    const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as {
      workspaces?: string[] | { packages?: string[] }
    }
    const declared = Array.isArray(manifest.workspaces) ? manifest.workspaces : manifest.workspaces?.packages
    for (const entry of declared ?? []) if (typeof entry === 'string') patterns.push(entry)
  } catch {
    // No root package.json, or unparseable — workspaces simply are not declared.
  }
  try {
    const workspace = parseYaml(await readFile(join(root, 'pnpm-workspace.yaml'), 'utf8')) as {
      packages?: unknown
    }
    if (Array.isArray(workspace?.packages)) {
      for (const entry of workspace.packages) if (typeof entry === 'string') patterns.push(entry)
    }
  } catch {
    // No pnpm workspace file, or unparseable.
  }
  const roots: string[] = []
  for (const pattern of patterns) {
    if (pattern.startsWith('!')) continue
    const prefix = pattern.split('*')[0].replace(/\/+$/, '')
    const first = prefix.split('/')[0]
    if (!first || first.startsWith('.') || SCAN_EXCLUDED_DIRECTORIES.has(first)) continue
    if (await safeDirectory(join(root, first))) roots.push(first)
  }
  return roots
}

/** Does this directory look like a nested project root (its own manifest or a conventional source child)? */
async function looksLikeProjectRoot(path: string): Promise<boolean> {
  for (const manifest of PROJECT_ROOT_MANIFESTS) {
    if (await exists(join(path, manifest))) return true
  }
  return safeDirectory(join(path, 'src'))
}

export async function suggestedAllowGlobs(root: string): Promise<string[]> {
  const names = new Set<string>()
  for (const directory of SUGGESTED_SCOPE_DIRECTORIES) {
    if (await safeDirectory(join(root, directory))) names.add(directory)
  }
  for (const declared of await workspaceDeclaredRoots(root)) names.add(declared)
  // Shallow scan for project roots the conventional list misses — a nested app
  // named after the product (selevita-app/) holds the actual work, and a scope
  // that omits it flags every legitimate edit. Only directories that carry
  // their own project manifest (or a src/ child) qualify, so junk directories
  // never widen an unattended --yes scope.
  let entries: Dirent[] = []
  try {
    entries = await readdir(root, { withFileTypes: true })
  } catch {
    // An unreadable root yields no scan suggestions; manifest roots stand.
  }
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue
    if (entry.name.startsWith('.') || SCAN_EXCLUDED_DIRECTORIES.has(entry.name) || names.has(entry.name)) continue
    if (await looksLikeProjectRoot(join(root, entry.name))) names.add(entry.name)
  }
  return [...names].map((name) => `${name}/**`)
}

async function resolveAllowGlobs(
  root: string,
  explicit: string[] | undefined,
  yes: boolean,
  ask: (question: string) => Promise<string>,
  write: (value: string) => void,
): Promise<string[]> {
  if (explicit?.length) return explicit
  const suggestions = await suggestedAllowGlobs(root)
  if (yes) {
    // Plug and play: an unattended run on an ordinary repository should end up
    // protected rather than stopped to look up glob syntax. Only conventional
    // roots that actually exist on disk are adopted, never a repository-wide
    // glob, and the choice is printed so an unattended decision stays
    // auditable. Verification-command trust is the genuinely dangerous
    // decision and is still withheld unless --trust-verify is passed.
    const detected = suggestions.filter((glob) => !repositoryWide(glob))
    if (!detected.length) {
      throw new Error('non-interactive setup requires at least one explicit --allow "src/**" value')
    }
    write(`Adopted detected allowed change roots: ${detected.join(', ')}\n`)
    return detected
  }

  if (suggestions.length) {
    write(`Suggested allowed change roots: ${suggestions.join(', ')}\n`)
  } else {
    write('No conventional source directories were found. Choose the paths agents are normally allowed to change.\n')
  }
  const answer = await ask(
    suggestions.length
      ? `Allowed roots (comma-separated) [${suggestions.join(', ')}]: `
      : 'Allowed roots (comma-separated, for example src/**, tests/**): ',
  )
  const selected = answer.trim() ? parsePromptGlobs(answer) : suggestions
  if (!selected.length) throw new Error('setup requires at least one allowed change root')
  if (selected.some(repositoryWide)) {
    write('Warning: a repository-wide allow glob weakens scope-drift detection.\n')
    const confirmation = await ask('Type "broad" to keep this repository-wide scope: ')
    if (confirmation.trim().toLowerCase() !== 'broad') throw new Error('repository-wide scope was not confirmed')
  }
  return selected
}

async function resolveHookTarget(
  requested: SetupHookTarget | undefined,
  yes: boolean,
  ask: (question: string) => Promise<string>,
): Promise<SetupHookTarget> {
  if (requested) return requested
  if (yes) return 'all'
  const answer = (await ask('Automatic checks [all] (all, pre-commit, claude, codex, none): ')).trim()
  return hookTarget(answer || 'all')!
}

/**
 * Commands the repository's own docs or workflows name, rendered with their
 * source so the human can judge them. Never recorded, never trusted here —
 * repository prose is untrusted input, and adopting a command stays a
 * deliberate two-step (write it into verify:, then codetruss verify-policy
 * trust).
 */
function documentedLines(detection: VerifyDetection): string[] {
  if (!detection.documented?.length) return []
  return [
    'Command-shaped lines found in this repository\'s docs and workflows (suggestions only, never auto-recorded or vetted):\n',
    ...detection.documented.map(({ command, source }) => `  - ${command}  (${source})\n`),
  ]
}

function detectionLines(detection: VerifyDetection, withheld: boolean): string[] {
  const list = detection.candidates.map((entry) => `  - ${entry}\n`)
  if (detection.commands.length) {
    return [
      'Detected repository verification commands but did NOT record them:\n',
      ...list,
      ...(withheld
        ? ['They execute repository code, and an unattended run must not approve that on your behalf.\n']
        : []),
      ...documentedLines(detection),
      `To enable them: add them under verify: in ${CONFIG_FILE}, then run codetruss verify-policy trust\n`,
    ]
  }
  if (detection.blocker === 'missing-lockfile') {
    return [
      'Found package.json scripts but recorded no verification commands:\n',
      ...list,
      'No lockfile is committed, so CodeTruss cannot tell which package manager runs them.\n',
      ...documentedLines(detection),
      `To enable them: commit a lockfile and rerun setup, or add the exact commands under verify: in ${CONFIG_FILE}, then run codetruss verify-policy trust\n`,
    ]
  }
  if (detection.blocker === 'package-manager-unavailable') {
    return [
      'Detected repository verification commands but their package manager is not on PATH:\n',
      ...list,
      ...documentedLines(detection),
      `To enable them: install the package manager and rerun setup, or add the exact commands under verify: in ${CONFIG_FILE}, then run codetruss verify-policy trust\n`,
    ]
  }
  if (detection.documented?.length) {
    return [
      'No runnable verification commands were detected. Command-shaped lines found in its docs and workflows (suggestions only, never vetted):\n',
      ...detection.documented.map(({ command, source }) => `  - ${command}  (${source})\n`),
      `To adopt one: add it under verify: in ${CONFIG_FILE}, then run codetruss verify-policy trust\n`,
    ]
  }
  return [`No repository verification commands were detected; add trusted checks to verify: in ${CONFIG_FILE} when ready.\n`]
}

function withSetupFootprint(globs: string[]): string[] {
  return [...globs, ...SETUP_FOOTPRINT_GLOBS.filter((glob) => !globs.includes(glob))]
}

/**
 * Does a stored allow list already express this request? Setup appends its own
 * footprint, so the saved policy is the request plus those globs — and a policy
 * saved by an earlier CLI carries the request alone. Both are the same ask, and
 * a rerun of the identical command must stay idempotent rather than error.
 */
function allowPolicyMatches(requested: string[], existing: string[]): boolean {
  const stored = JSON.stringify(existing)
  return stored === JSON.stringify(requested) || stored === JSON.stringify(withSetupFootprint(requested))
}

/** Report what detection actually found, including what setup chose to withhold. */
async function writeVerifyDetectionTruth(
  root: string,
  withheld: boolean,
  write: (value: string) => void,
): Promise<void> {
  for (const line of detectionLines(await detectVerifyCommands(root), withheld)) write(line)
}

/**
 * One guided, resumable setup path. Repository verification commands are
 * displayed before their exact path-bound fingerprint is trusted. `--yes`
 * deliberately does not imply command trust.
 */
export async function guidedSetup(root: string, options: GuidedSetupOptions = {}): Promise<number> {
  const input = options.input ?? process.stdin
  const output = options.output ?? process.stdout
  const write = (value: string) => { output.write(value) }
  const allow = normalizeGlobs(options.allow, 'allow')
  const deny = normalizeGlobs(options.deny, 'deny')
  const requestedHooks = hookTarget(options.hooks)
  const yes = options.yes === true
  let withheldVerify = false
  let readline: ReturnType<typeof createInterface> | undefined
  let answers: AsyncIterableIterator<string> | undefined
  const ask = options.ask ?? (async (question: string) => {
    if (!readline) {
      readline = createInterface({ input, output })
      answers = readline[Symbol.asyncIterator]()
    }
    output.write(question)
    const answer = await answers!.next()
    if (answer.done) throw new Error('setup input ended before every required confirmation')
    return answer.value
  })

  try {
    write('CodeTruss guided setup — local only; nothing is uploaded.\n')
    await ensureLocalEvidenceProtected(root)
    const configPath = join(root, CONFIG_FILE)
    const hasConfig = await exists(configPath)
    if (hasConfig) {
      const existing = await loadConfig(root)
      const allowChanged = allow !== undefined && !allowPolicyMatches(allow, existing.allow)
      const denyChanged = deny !== undefined && JSON.stringify(deny) !== JSON.stringify(existing.deny)
      if (allowChanged || denyChanged) {
        throw new Error(`${CONFIG_FILE} already exists with a different ${allowChanged ? 'allow' : 'deny'} policy; edit and review it directly, then rerun setup`)
      }
      write(`${allow !== undefined || deny !== undefined ? 'Requested policy matches' : 'Using existing'} ${CONFIG_FILE}.\n`)
    } else {
      const selectedAllow = withSetupFootprint(await resolveAllowGlobs(root, allow, yes, ask, write))
      const selectedDeny = deny ?? []
      // Unattended setup must never record commands it has no permission to
      // run: an untrusted verify list makes every later review exit 3 with no
      // receipt, which is worse than having no verification configured.
      // Only when hooks will actually be installed: with --hooks none there is
      // nothing to block, and recording untrusted commands for later inspection
      // is the point of that flow.
      withheldVerify = yes && !options.trustVerify && requestedHooks !== 'none'
      const path = await initialize(root, false, {
        allow: selectedAllow,
        deny: selectedDeny,
        ...(withheldVerify ? { verify: [] } : {}),
      })
      write(`Saved policy: ${path}\n`)
      write(`Commit ${CONFIG_FILE} so this policy is reviewable.\n`)
    }

    const config = await loadConfig(root)
    if (!config.allow.length) {
      throw new Error(`${CONFIG_FILE} has no allowed change roots; define at least one allow glob and rerun codetruss setup`)
    }
    write(`Allowed: ${config.allow.join(', ')}\n`)
    write(`Denied: ${config.deny.length ? config.deny.join(', ') : '(none; sensitive surfaces still require review)'}\n`)

    if (config.verify.length) {
      write('Detected repository verification commands:\n')
      for (const command of config.verify) write(`  - ${command}\n`)
      write('These commands execute repository code, each in its own isolated snapshot.\n')
    } else {
      // "No commands were detected" was a lie in the two most common cases: an
      // unattended run deliberately withheld them, or detection found the
      // scripts and could not resolve a package manager. Report what was
      // actually found and what clears it.
      await writeVerifyDetectionTruth(root, withheldVerify, write)
    }

    const selectedHooks = await resolveHookTarget(requestedHooks, yes, ask)
    if (config.verify.length) {
      const currentTrust = await verifyCommandTrustStatus(root, config.verify)
      write(`Verification fingerprint: ${currentTrust.hash}\n`)
      if (currentTrust.trusted) {
        write('Verification commands are already trusted for this repository path.\n')
      } else if (selectedHooks === 'none' && !options.trustVerify) {
        write('Verification commands remain untrusted; after inspection, run codetruss verify-policy trust before reviews execute them.\n')
      } else {
        if (options.trustVerify) {
          await trustVerifyCommands(root, config.verify)
          write('Trusted the exact verification command list shown above.\n')
        } else if (yes) {
          write('Verification commands are NOT trusted and were left out of the policy; inspect them, then run codetruss verify-policy trust (or rerun setup with --trust-verify) to enable them.\n')
        } else {
          const approval = await ask('Type "trust" to approve this exact command list for automatic checks: ')
          if (approval.trim().toLowerCase() !== 'trust') {
            write('Setup paused before hook installation. The policy is saved, but repository commands remain untrusted.\n')
            write('After inspection: codetruss verify-policy trust && codetruss setup\n')
            return 3
          }
          await trustVerifyCommands(root, config.verify)
          write('Trusted the exact verification command list shown above.\n')
        }
      }
    }

    if (selectedHooks === 'none') {
      write('Policy ready. Automatic hooks were not installed. Run codetruss hooks install all when ready.\n')
      write('Receipts stay on this machine unless you explicitly run codetruss sync.\n')
      return 0
    }

    await installHooks(root, selectedHooks)
    const doctor = await inspectHookDoctor(root, selectedHooks)
    const errors = doctor.checks.filter((check) => check.level === 'error')
    const warnings = doctor.checks.filter((check) => check.level === 'warning' && check.target !== 'codex')
    for (const check of [...errors, ...warnings]) {
      write(`${check.level.toUpperCase()} ${check.target}: ${check.message}${check.path ? ` (${check.path})` : ''}\n`)
    }
    if (errors.length) throw new Error(`hook health check found ${errors.length} error(s); run codetruss hooks doctor ${selectedHooks}`)

    const codexSelected = selectedHooks === 'all' || selectedHooks === 'codex'
    if (selectedHooks === 'codex') write('INSTALLED: Codex automatic checks are configured but are not active until project-hook approval.\n')
    else write(`READY: ${selectedHooks === 'all' ? 'pre-commit and Claude' : selectedHooks} automatic checks are active.\n`)
    if (warnings.length) write(`Hook health has ${warnings.length} warning(s); run codetruss hooks doctor ${selectedHooks} for detail.\n`)
    if (codexSelected) {
      write('ACTION REQUIRED FOR CODEX: open /hooks once and trust this exact project hook. Changed hook definitions require review again.\n')
    }
    if (selectedHooks === 'codex') write('After that approval, use Codex normally; no per-change CodeTruss command is required.\n')
    else if (selectedHooks === 'all') write('Use Claude Code or your normal commit flow now; after the Codex approval above, use Codex normally too. No per-change CodeTruss command is required.\n')
    else if (selectedHooks === 'claude') write('Use Claude Code normally; no per-change CodeTruss command is required.\n')
    else write('Use your normal commit flow; no per-change CodeTruss command is required.\n')
    write(`Undo automatic checks: codetruss hooks uninstall ${selectedHooks}\n`)
    write('Receipts stay on this machine unless you explicitly run codetruss sync.\n')
    return 0
  } finally {
    readline?.close()
  }
}
