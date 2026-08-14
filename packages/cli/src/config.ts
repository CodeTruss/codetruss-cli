import { access, lstat, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { constants as fsConstants, lstatSync } from 'node:fs'
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { parse, stringify } from 'yaml'
import { loadSigningKey, normalizePublicKey } from './signing.js'
import { CONFIG_LLM_PROVIDERS, type CliConfig } from './types.js'

export const CONFIG_FILE = '.codetruss.yml'
export const PRODUCTION_SYNC_ORIGIN = 'https://codetruss.com'
export const DEV_SYNC_ORIGIN_ENV = 'CODETRUSS_DEV_SYNC_ORIGIN'
export const APPROVED_RECEIPT_DIR = '.codetruss/receipts'
/**
 * Normalize the signing pin into a set. Accepts a single `publicKey` (what
 * `init` writes) and/or a `publicKeys` list, so a team can add each developer's
 * key without any one of them being blocked. Duplicates collapse; order is
 * preserved so `publicKey` stays stable for existing single-signer configs.
 */
function signingPins(signing: Record<string, unknown>): { publicKey?: string; publicKeys: string[] } {
  const raw: unknown[] = [
    signing.publicKey,
    ...(Array.isArray(signing.publicKeys) ? signing.publicKeys : []),
  ]
  const publicKeys: string[] = []
  for (const entry of raw) {
    if (typeof entry !== 'string' || !entry.trim()) continue
    const normalized = normalizePublicKey(entry)
    if (!publicKeys.includes(normalized)) publicKeys.push(normalized)
  }
  return { publicKey: publicKeys[0], publicKeys }
}

export const DEFAULT_CONFIG: CliConfig = {
  version: 1,
  allow: [],
  deny: [],
  exclude: [],
  verify: [],
  receipts: { dir: APPROVED_RECEIPT_DIR },
  llm: { maxDiffBytes: 200_000 },
  signing: { publicKeys: [] },
  sync: { url: PRODUCTION_SYNC_ORIGIN },
}

export interface InitializeOptions {
  allow?: string[]
  deny?: string[]
  /**
   * Override the auto-detected verification commands. Unattended setup passes
   * an empty list so a repository is never configured with commands it has not
   * been given permission to run — a review would otherwise refuse to produce
   * any receipt at all.
   */
  verify?: string[]
}

function objectValue(value: unknown, key: string): Record<string, unknown> {
  if (value === undefined) return {}
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${key} must be a YAML object`)
  return value as Record<string, unknown>
}

/**
 * A repository may retain the old production-only sync stanza for backwards
 * compatibility, but it can never choose where a bearer credential is sent.
 */
function assertSafeRepoSync(value: unknown): void {
  if (value === undefined) return
  const sync = objectValue(value, 'sync')
  const keys = Object.keys(sync)
  if (keys.length === 0) return
  if (keys.length === 1 && sync.url === PRODUCTION_SYNC_ORIGIN) return
  throw new Error(
    `${CONFIG_FILE} cannot configure a sync destination; production sync is fixed to ${PRODUCTION_SYNC_ORIGIN}`,
  )
}

/**
 * Scope globs are matched with `minimatch`, whose brace expansion is
 * combinatorial in the pattern, and `allow`/`deny`/`exclude` arrive from the
 * scanned repository's `.codetruss.yml` — a file CodeTruss did not write. A
 * 7.5 KB pattern of repeated `{a,b}` groups ended 0.2.45 in an uncatchable
 * out-of-memory abort before it could report anything. `brace-expansion` bounds
 * that now, but the shape recurs with any matcher that is superlinear in its
 * pattern, so the untrusted side is bounded here as well. Real globs are nowhere
 * near these limits: the longest in this repository's own policy is under 50
 * characters with two brace groups.
 */
export const MAX_SCOPE_GLOB_LENGTH = 512
export const MAX_SCOPE_GLOB_BRACE_GROUPS = 16
export const MAX_SCOPE_GLOB_EXPANSIONS = 1024

/** How many alternatives one brace group contributes: `{a,b}` is 2, `{1..40}` is 40. */
function braceAlternatives(body: string, commas: number): number {
  if (commas > 0) return commas + 1
  // A sequence expression carries no comma and still expands: `{1..9}`, `{a..z}`.
  const sequence = /^(-?\d+|[a-zA-Z])\.\.(-?\d+|[a-zA-Z])(?:\.\.(-?\d+))?$/.exec(body)
  if (!sequence) return 1
  const [, from, to, step] = sequence
  const ordinal = (part: string) => /^-?\d+$/.test(part) ? Number(part) : part.charCodeAt(0)
  const stride = Math.abs(Number(step ?? '1')) || 1
  return Math.floor(Math.abs(ordinal(to!) - ordinal(from!)) / stride) + 1
}

/**
 * An upper bound on what brace expansion can produce. Nesting only ever yields
 * fewer patterns than the product of every group's alternatives, so this
 * over-counts rather than under-counts. A count that is not a finite number
 * saturates instead of poisoning the comparison with NaN.
 */
function braceBound(glob: string): { groups: number; expansions: number } {
  const saturate = (value: number) => Number.isFinite(value)
    ? Math.min(value, MAX_SCOPE_GLOB_EXPANSIONS + 1)
    : MAX_SCOPE_GLOB_EXPANSIONS + 1
  const open: { commas: number; bodyStart: number }[] = []
  let groups = 0
  let expansions = 1
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index]
    // An escaped brace is a literal to minimatch, so it opens no group.
    if (character === '\\') { index += 1; continue }
    if (character === '{') { open.push({ commas: 0, bodyStart: index + 1 }); groups += 1; continue }
    const group = open.at(-1)
    if (!group) continue
    if (character === ',') { group.commas += 1; continue }
    if (character === '}') {
      open.pop()
      expansions = saturate(expansions * braceAlternatives(glob.slice(group.bodyStart, index), group.commas))
    }
  }
  return { groups, expansions }
}

/** Enough of the pattern to find the offending line, without pasting kilobytes into a terminal. */
function excerpt(glob: string): string {
  return glob.length > 60 ? `${glob.slice(0, 60)}…` : glob
}

/**
 * Reject an oversized scope glob and name it. Truncating the pattern instead
 * would silently enforce a policy nobody wrote.
 */
export function boundedScopeGlobs(globs: string[], name: string): string[] {
  for (const glob of globs) {
    if (glob.length > MAX_SCOPE_GLOB_LENGTH) {
      throw new Error(`${name} glob is ${glob.length} characters, over the ${MAX_SCOPE_GLOB_LENGTH}-character limit: ${excerpt(glob)}`)
    }
    const { groups, expansions } = braceBound(glob)
    if (groups > MAX_SCOPE_GLOB_BRACE_GROUPS) {
      throw new Error(`${name} glob has ${groups} brace groups, over the limit of ${MAX_SCOPE_GLOB_BRACE_GROUPS}: ${excerpt(glob)}`)
    }
    if (expansions > MAX_SCOPE_GLOB_EXPANSIONS) {
      throw new Error(`${name} glob expands to more than ${MAX_SCOPE_GLOB_EXPANSIONS} patterns: ${excerpt(glob)}`)
    }
  }
  return globs
}

export async function loadConfig(root: string): Promise<CliConfig> {
  const path = join(root, CONFIG_FILE)
  let raw: unknown
  try {
    raw = parse(await readFile(path, 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return structuredClone(DEFAULT_CONFIG)
    throw new Error(`could not read ${CONFIG_FILE}: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`${CONFIG_FILE} must contain a YAML object`)
  const value = raw as Record<string, unknown>
  const list = (key: string) => {
    const input = value[key]
    if (input === undefined) return []
    if (!Array.isArray(input) || input.some((item) => typeof item !== 'string' || !item.trim())) throw new Error(`${key} must be a list of non-empty strings`)
    return input as string[]
  }
  if (value.version !== undefined && value.version !== 1) throw new Error(`unsupported config version ${String(value.version)}`)
  const receipts = objectValue(value.receipts, 'receipts')
  const llm = objectValue(value.llm, 'llm')
  const signing = objectValue(value.signing, 'signing')
  assertSafeRepoSync(value.sync)
  const provider = llm.provider
  if (provider !== undefined && !CONFIG_LLM_PROVIDERS.includes(String(provider) as typeof CONFIG_LLM_PROVIDERS[number])) throw new Error(`unsupported llm.provider ${String(provider)}`)
  const model = llm.model
  const maxDiffBytes = llm.maxDiffBytes
  return {
    version: 1,
    allow: boundedScopeGlobs(list('allow'), 'allow'),
    deny: boundedScopeGlobs(list('deny'), 'deny'),
    exclude: boundedScopeGlobs(list('exclude'), 'exclude'),
    verify: list('verify'),
    receipts: { dir: typeof receipts.dir === 'string' ? receipts.dir : DEFAULT_CONFIG.receipts.dir },
    llm: {
      provider: provider as CliConfig['llm']['provider'],
      model: typeof model === 'string' && model.trim() ? model.trim() : undefined,
      // Legacy repositories may contain a value that current provider review
      // rejects. Keep deterministic commands readable; enforce the hard bound
      // only when --llm is actually requested.
      maxDiffBytes: typeof maxDiffBytes === 'number' && maxDiffBytes > 0 ? maxDiffBytes : DEFAULT_CONFIG.llm.maxDiffBytes,
    },
    signing: signingPins(signing),
    // This value is an application invariant, never repository configuration.
    sync: { url: PRODUCTION_SYNC_ORIGIN },
  }
}

export function receiptDir(root: string, config: CliConfig): string {
  const requested = config.receipts.dir.trim()
  if (!requested || isAbsolute(requested)) {
    throw new Error(`receipts.dir must stay under ${APPROVED_RECEIPT_DIR}`)
  }
  const repoRoot = resolve(root)
  const approvedRoot = resolve(repoRoot, APPROVED_RECEIPT_DIR)
  const candidate = resolve(repoRoot, requested)
  const withinApprovedRoot = relative(approvedRoot, candidate)
  if (withinApprovedRoot === '..' || withinApprovedRoot.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(withinApprovedRoot)) {
    throw new Error(`receipts.dir must stay under ${APPROVED_RECEIPT_DIR}`)
  }
  let cursor = repoRoot
  for (const part of relative(repoRoot, candidate).split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    try {
      if (lstatSync(cursor).isSymbolicLink()) {
        throw new Error(`receipts.dir must not traverse symbolic links under ${APPROVED_RECEIPT_DIR}`)
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') break
      throw error
    }
  }
  return candidate
}

/**
 * Resolve the only destination to which the CLI may attach CODETRUSS_API_KEY.
 * Production is hard-bound to CodeTruss over HTTPS. The sole override is an
 * explicit user-owned environment value and is deliberately limited to a
 * loopback development server.
 */
export function resolveSyncOrigin(explicitDevOrigin = process.env[DEV_SYNC_ORIGIN_ENV]): string {
  if (explicitDevOrigin === undefined || explicitDevOrigin.trim() === '') return PRODUCTION_SYNC_ORIGIN
  let parsed: URL
  try {
    parsed = new URL(explicitDevOrigin)
  } catch {
    throw new Error(`${DEV_SYNC_ORIGIN_ENV} must be an http(s) loopback origin`)
  }
  const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])
  const hasOnlyOrigin = parsed.pathname === '/' && !parsed.search && !parsed.hash && !parsed.username && !parsed.password
  if (!['http:', 'https:'].includes(parsed.protocol) || !loopbackHosts.has(parsed.hostname) || !hasOnlyOrigin) {
    throw new Error(`${DEV_SYNC_ORIGIN_ENV} must be an http(s) loopback origin without credentials, path, query, or fragment`)
  }
  return parsed.origin
}

function initializeGlobs(value: string[] | undefined, name: 'allow' | 'deny'): string[] {
  if (value === undefined) return []
  if (!Array.isArray(value) || value.some((glob) => typeof glob !== 'string' || !glob.trim())) {
    throw new Error(`init ${name} globs must be non-empty strings`)
  }
  return boundedScopeGlobs(value.map((glob) => glob.trim()), `init ${name}`)
}

export async function initialize(root: string, force = false, options: InitializeOptions = {}): Promise<string> {
  const allow = initializeGlobs(options.allow, 'allow')
  const deny = initializeGlobs(options.deny, 'deny')
  const path = join(root, CONFIG_FILE)
  if (!force) {
    try { await access(path); throw new Error(`${CONFIG_FILE} already exists; pass --force to replace it`) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
  }
  const detected = options.verify ?? (await detectVerify(root))
  const key = await loadSigningKey(true)
  const value = {
    version: DEFAULT_CONFIG.version,
    allow,
    deny,
    // Written empty so the key is discoverable in the file a user already has,
    // rather than only in documentation they have not read yet.
    exclude: [],
    verify: detected,
    receipts: DEFAULT_CONFIG.receipts,
    llm: DEFAULT_CONFIG.llm,
    signing: { publicKey: key.publicKey },
  }
  await mkdir(dirname(path), { recursive: true })
  await writeFile(
    path,
    '# CodeTruss local agent guardrails. Deny wins; unmatched paths are unexpected.\n'
    + '# exclude: globs to keep OUT of analysis (still inventoried, still disclosed on the receipt).\n'
    + stringify(value),
    'utf8',
  )
  await mkdir(join(root, DEFAULT_CONFIG.receipts.dir), { recursive: true })
  return path
}

/**
 * Why auto-detection found nothing, when the answer is actionable. Setup used
 * to print a flat "no commands were detected", which reads as "this repository
 * has no tests" even when the repository has `"test": "vitest run"` and is one
 * `npm install` away from a lockfile.
 */
export type VerifyDetectionBlocker = 'missing-lockfile' | 'package-manager-unavailable'

export interface VerifyDetection {
  /** Commands safe to record. Empty whenever a blocker is set. */
  commands: string[]
  blocker?: VerifyDetectionBlocker
  /**
   * What was found: full commands when the package manager is known, bare
   * script names under `missing-lockfile`, where no manager could be resolved.
   */
  candidates: string[]
  /**
   * Commands the repository's own prose documents — README, docs/*.md,
   * workflow run steps. Suggestions ONLY: they are shown with their source
   * file and are never recorded into `verify:`, because repository text is
   * untrusted input. Adopting one requires a human to write it into
   * `.codetruss.yml` and run `codetruss verify-policy trust`.
   */
  documented?: { command: string; source: string }[]
}

/** Runners a documented suggestion may begin with; anything else is prose. */
const DOCUMENTED_COMMAND_RUNNERS = new Set([
  'tsc', 'pnpm', 'npm', 'npx', 'yarn', 'node', 'vitest', 'jest', 'eslint', 'prettier',
  'pytest', 'ruff', 'mypy', 'go', 'cargo', 'make', 'tsx',
])
const DOCUMENTED_FILE_LIMIT = 24
const DOCUMENTED_BYTES_PER_FILE = 262_144
const DOCUMENTED_RESULT_LIMIT = 8

/**
 * One argv-shaped command line, or nothing. Shell composition of any kind —
 * pipes, chaining, redirection, substitution — is rejected outright: a
 * malicious doc can at worst DISPLAY a command labeled with its source file,
 * and even the display refuses anything that is not a single plain invocation.
 */
function documentedCommand(line: string): string | undefined {
  const trimmed = line.trim().replace(/^\$\s+/, '')
  if (!trimmed || trimmed.length > 200) return undefined
  if (!/^[\w./@:=\- ]+$/.test(trimmed)) return undefined
  const runner = trimmed.split(/\s+/)[0]
  return DOCUMENTED_COMMAND_RUNNERS.has(runner) ? trimmed : undefined
}

function commandsFromMarkdown(text: string): string[] {
  const results: string[] = []
  for (const match of text.matchAll(/```[^\n]*\n([\s\S]*?)```/g)) {
    for (const line of match[1].split('\n')) {
      const command = documentedCommand(line)
      if (command) results.push(command)
    }
  }
  for (const match of text.matchAll(/`([^`\n]+)`/g)) {
    const command = documentedCommand(match[1])
    if (command) results.push(command)
  }
  return results
}

function commandsFromWorkflow(text: string): string[] {
  const results: string[] = []
  let parsed: unknown
  try {
    parsed = parse(text)
  } catch {
    return results
  }
  const jobs = (parsed as { jobs?: unknown })?.jobs
  if (!jobs || typeof jobs !== 'object') return results
  for (const job of Object.values(jobs as Record<string, { steps?: { run?: unknown }[] }>)) {
    if (!job || !Array.isArray(job.steps)) continue
    for (const step of job.steps) {
      if (typeof step?.run !== 'string') continue
      for (const line of step.run.split('\n')) {
        const command = documentedCommand(line)
        if (command) results.push(command)
      }
    }
  }
  return results
}

/**
 * The gate a repository documents for itself — a handover doc spelling out
 * `tsc --noEmit`, a workflow running the real checks — mined so setup can say
 * "found in docs/HANDOVER.md, not recorded" instead of the false "no
 * verification commands were detected". Bounded reads; display-only output.
 */
async function mineDocumentedVerifyCandidates(
  root: string,
  known: Iterable<string>,
): Promise<{ command: string; source: string }[]> {
  // The source label prints in setup output, so a filename is held to the
  // same byte discipline as a command: no control characters, no spaces, no
  // surprises. Files with wilder names are simply not mined.
  const safeName = (name: string) => /^[\w.\-]{1,120}$/.test(name)
  const sources: { path: string; extract: (text: string) => string[] }[] = [
    { path: 'README.md', extract: commandsFromMarkdown },
  ]
  try {
    for (const entry of await readdir(join(root, 'docs'), { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.md') && safeName(entry.name)) {
        sources.push({ path: `docs/${entry.name}`, extract: commandsFromMarkdown })
      }
    }
  } catch {
    // No docs directory.
  }
  try {
    for (const entry of await readdir(join(root, '.github', 'workflows'), { withFileTypes: true })) {
      if (entry.isFile() && /\.ya?ml$/.test(entry.name) && safeName(entry.name)) {
        sources.push({ path: `.github/workflows/${entry.name}`, extract: commandsFromWorkflow })
      }
    }
  } catch {
    // No workflows directory.
  }
  const documented: { command: string; source: string }[] = []
  const seen = new Set(known)
  for (const source of sources.slice(0, DOCUMENTED_FILE_LIMIT)) {
    let text: string
    try {
      // lstat, not stat: a symlinked doc could otherwise walk the miner out
      // of the repository entirely.
      const metadata = await lstat(join(root, source.path))
      if (!metadata.isFile() || metadata.size > DOCUMENTED_BYTES_PER_FILE) continue
      text = await readFile(join(root, source.path), 'utf8')
    } catch {
      continue
    }
    for (const command of source.extract(text)) {
      if (seen.has(command)) continue
      seen.add(command)
      documented.push({ command, source: source.path })
      if (documented.length >= DOCUMENTED_RESULT_LIMIT) return documented
    }
  }
  return documented
}

async function detectVerify(root: string): Promise<string[]> {
  return (await detectVerifyCommands(root)).commands
}

export async function detectVerifyCommands(root: string): Promise<VerifyDetection> {
  const detection = await recordableVerifyDetection(root)
  const documented = await mineDocumentedVerifyCandidates(root, [...detection.commands, ...detection.candidates])
  return documented.length ? { ...detection, documented } : detection
}

async function recordableVerifyDetection(root: string): Promise<VerifyDetection> {
  const exists = async (name: string) => access(join(root, name)).then(() => true, () => false)
  // Detect commands without executing repository-controlled code. This also
  // recognizes Windows package-manager shims such as `pnpm.cmd`.
  const available = async (command: string): Promise<boolean> => {
    const extensions = process.platform === 'win32'
      ? (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').map((extension) => extension.trim()).filter(Boolean)
      : ['']
    const path = process.env.PATH ?? process.env.Path ?? process.env.path ?? ''
    for (const rawDirectory of path.split(delimiter).filter(Boolean)) {
      const directory = rawDirectory.startsWith('"') && rawDirectory.endsWith('"')
        ? rawDirectory.slice(1, -1)
        : rawDirectory
      for (const extension of extensions) {
        const candidate = join(directory, `${command}${extension}`)
        const isFile = await stat(candidate).then((metadata) => metadata.isFile(), () => false)
        if (!isFile) continue
        if (process.platform === 'win32') return true
        if (await access(candidate, fsConstants.X_OK).then(() => true, () => false)) return true
      }
    }
    return false
  }
  const packageScripts = async (): Promise<Record<string, unknown>> => {
    try {
      const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as { scripts?: unknown }
      return pkg.scripts && typeof pkg.scripts === 'object' && !Array.isArray(pkg.scripts)
        ? pkg.scripts as Record<string, unknown>
        : {}
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {}
      throw new Error(`could not inspect package.json: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  /** The same [lint, typecheck, test] collection for every Node package manager. */
  const nodeScripts = async (
    manager: 'pnpm' | 'npm' | 'yarn',
    format: (name: string) => string,
  ): Promise<VerifyDetection> => {
    const scripts = await packageScripts()
    const candidates = ['lint', 'typecheck', 'test'].filter((name) => typeof scripts[name] === 'string').map(format)
    if (!candidates.length) return { commands: [], candidates: [] }
    return await available(manager)
      ? { commands: candidates, candidates }
      : { commands: [], candidates, blocker: 'package-manager-unavailable' }
  }

  if (await exists('pnpm-lock.yaml')) return nodeScripts('pnpm', (name) => `pnpm ${name}`)
  // `npm lint` is not a command; only lifecycle names run without `run`.
  if (await exists('package-lock.json')) return nodeScripts('npm', (name) => `npm run ${name}`)
  if (await exists('yarn.lock')) return nodeScripts('yarn', (name) => `yarn ${name}`)
  if ((await exists('go.mod')) && await available('go')) return { commands: ['go test ./...'], candidates: ['go test ./...'] }
  if ((await exists('Cargo.toml')) && await available('cargo')) return { commands: ['cargo test'], candidates: ['cargo test'] }
  if (((await exists('pyproject.toml')) || (await exists('requirements.txt'))) && await available('pytest')) {
    return { commands: ['pytest'], candidates: ['pytest'] }
  }
  // A package.json with runnable scripts and no lockfile is the common case
  // where detection legitimately fails: CodeTruss cannot tell which package
  // manager to invoke. Say that, rather than implying there is nothing to run.
  const scripts = await packageScripts()
  const candidates = ['lint', 'typecheck', 'test'].filter((name) => typeof scripts[name] === 'string')
  if (candidates.length) return { commands: [], candidates, blocker: 'missing-lockfile' }
  return { commands: [], candidates: [] }
}

/**
 * Append the local signing key to the repository's trusted set so a teammate
 * can produce receipts under their OWN identity. The alternative the old error
 * implied — sharing a private key — would destroy per-signer attribution, which
 * is the entire point of signing the receipt.
 */
export async function trustLocalSigningKey(
  root: string,
): Promise<{ status: 'added' | 'already-trusted'; fingerprint: string; total: number }> {
  const key = await loadSigningKey(true)
  const path = join(root, CONFIG_FILE)
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    throw new Error(`no ${CONFIG_FILE} in this repository; run codetruss init first`)
  }
  const parsed = parse(text)
  const document = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {}
  const existing = signingPins(objectValue(document.signing, 'signing'))
  const mine = normalizePublicKey(key.publicKey)
  if (existing.publicKeys.includes(mine)) {
    return { status: 'already-trusted', fingerprint: key.fingerprint, total: existing.publicKeys.length }
  }
  const publicKeys = [...existing.publicKeys, mine]
  document.signing = { publicKeys }
  // Preserve the leading header comment; `stringify` would otherwise drop it.
  const header = text.startsWith('#') ? `${text.slice(0, text.indexOf('\n') + 1)}` : ''
  await writeFile(path, `${header}${stringify(document)}`, 'utf8')
  return { status: 'added', fingerprint: key.fingerprint, total: publicKeys.length }
}
