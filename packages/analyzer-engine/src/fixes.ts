import type { FindingFix } from './types'

/**
 * Builders for `AnalyzerFinding.fix`.
 *
 * Every builder here is total and honest: it returns `undefined` the moment the
 * evidence stops determining a single correct change, so the caller falls back
 * to prose guidance instead of shipping a plausible-looking wrong edit. Nothing
 * in this module touches the filesystem — a fix is text for a human or an agent
 * to read, never an action CodeTruss performs.
 */

/** How each language reads an environment variable at runtime. */
const ENV_ACCESSOR: Record<string, (name: string) => string> = {
  ts: (name) => `process.env.${name}`,
  tsx: (name) => `process.env.${name}`,
  mts: (name) => `process.env.${name}`,
  cts: (name) => `process.env.${name}`,
  js: (name) => `process.env.${name}`,
  jsx: (name) => `process.env.${name}`,
  mjs: (name) => `process.env.${name}`,
  cjs: (name) => `process.env.${name}`,
  py: (name) => `os.environ["${name}"]`,
  go: (name) => `os.Getenv("${name}")`,
  rb: (name) => `ENV.fetch("${name}")`,
  php: (name) => `getenv('${name}')`,
}

/** Languages whose accessor needs an import the file may not already have. */
const ACCESSOR_NEEDS_IMPORT = new Set(['py', 'go'])

function extensionOf(path: string): string {
  const base = path.split('/').pop() ?? path
  const dot = base.lastIndexOf('.')
  return dot <= 0 ? '' : base.slice(dot + 1).toLowerCase()
}

/**
 * `awsSecretKey` → `AWS_SECRET_KEY`. Returns undefined for identifiers that
 * cannot produce a legal environment-variable name, rather than guessing one.
 */
export function envVarNameFrom(identifier: string): string | undefined {
  const screaming = identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase()
  return /^[A-Z][A-Z0-9_]*$/.test(screaming) ? screaming : undefined
}

interface ParsedAssignment {
  /** Everything on the line before the opening quote. */
  head: string
  /** Everything after the closing quote. */
  tail: string
  quote: string
  identifier: string
  value: string
}

/** `const awsKey: string = "…"` / `let x = '…'` / `AWS_KEY = "…"`. */
const ASSIGNMENT_RE =
  /^(\s*(?:(?:export|public|private|protected|static|final|readonly|const|let|var|val)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]*?)?\s*=\s*)(['"])([^'"]*)\3(\s*[;,]?\s*)$/

/** `password: "…"` inside an object literal or a Python dict. */
const KEY_VALUE_RE =
  /^(\s*['"]?([A-Za-z_$][A-Za-z0-9_$-]*)['"]?\s*:\s*)(['"])([^'"]*)\3(\s*,?\s*)$/

/**
 * Parse a single-literal assignment. Lines with more than one string literal,
 * concatenation, or a call around the value are rejected: the replacement would
 * be a guess about which fragment is the credential.
 */
export function parseSingleLiteralAssignment(lineText: string): ParsedAssignment | undefined {
  const match = ASSIGNMENT_RE.exec(lineText) ?? KEY_VALUE_RE.exec(lineText)
  if (!match) return undefined
  return { head: match[1], identifier: match[2], quote: match[3], value: match[4], tail: match[5] }
}

/** Unified-diff hunk header for replacing exactly one line in place. */
function replaceLineHunk(path: string, line: number, before: string, after: string): string[] {
  return [`--- a/${path}`, `+++ b/${path}`, `@@ -${line} +${line} @@`, `-${before}`, `+${after}`]
}

/** Unified-diff hunk that appends one line to an existing or absent file. */
function appendLineHunk(path: string, existingLines: number | undefined, added: string): string[] {
  if (existingLines === undefined) {
    return [`--- /dev/null`, `+++ b/${path}`, `@@ -0,0 +1 @@`, `+${added}`]
  }
  return [`--- a/${path}`, `+++ b/${path}`, `@@ -${existingLines},0 +${existingLines + 1} @@`, `+${added}`]
}

export interface SecretFixEvidence {
  filePath: string
  line: number
  /** The exact source line the secret pattern matched. */
  lineText: string
  /** Human name of the credential type, used only in the redaction marker. */
  credentialType: string
  /** Line count of the repository's `.env.example`, or undefined when absent. */
  envExampleLines?: number
}

/**
 * Move-to-env refactor for a credential committed in source.
 *
 * The removed line is shown with the VALUE MASKED — CodeTruss never echoes a
 * credential, not even into its own suggestion — which is also why the diff is
 * deliberately not directly appliable. The safety note says so, and leads with
 * rotation: replacing the line does not remove the value from Git history.
 */
export function moveSecretToEnvFix(evidence: SecretFixEvidence): FindingFix | undefined {
  const extension = extensionOf(evidence.filePath)
  const accessor = ENV_ACCESSOR[extension]
  if (!accessor) return undefined
  const parsed = parseSingleLiteralAssignment(evidence.lineText)
  if (!parsed) return undefined
  // The parsed literal must be the one the scanner matched, or the replacement
  // would rewrite an unrelated string on a line that also carries a secret.
  if (!evidence.lineText.includes(parsed.value) || parsed.value.length === 0) return undefined
  const variable = envVarNameFrom(parsed.identifier)
  if (!variable) return undefined

  const masked = `${parsed.head}${parsed.quote}<${evidence.credentialType} value — never printed by CodeTruss>${parsed.quote}${parsed.tail}`
  const replaced = `${parsed.head}${accessor(variable)}${parsed.tail.replace(/^\s*/, '')}`
  const content = [
    ...replaceLineHunk(evidence.filePath, evidence.line, masked, replaced),
    ...appendLineHunk('.env.example', evidence.envExampleLines, `${variable}=`),
    '',
  ].join('\n')

  const importNote = ACCESSOR_NEEDS_IMPORT.has(extension)
    ? ` Add the import the accessor needs (\`os\`) if this file does not already have it.`
    : ''
  return {
    description: `Read the credential from \`${variable}\` at runtime and document it in .env.example.`,
    kind: 'diff',
    language: 'diff',
    content,
    safetyNote:
      `Rotate this credential first — it is already in Git history, and editing the line does not remove it from earlier commits. `
      + `The removed line is shown with the value masked, so this diff will NOT apply cleanly by design; make the edit by hand.${importNote}`,
  }
}

/**
 * A committed `.env`: the fix is to stop tracking the file, not to rewrite a
 * line. Concrete because the path is known; history rewriting is named as a
 * separate decision rather than scripted.
 */
export function untrackEnvFileFix(filePath: string): FindingFix {
  const content = [
    '# 1. Rotate every credential in this file at its provider first.',
    `# 2. Stop tracking the file (this does NOT remove it from earlier commits):`,
    `git rm --cached ${filePath}`,
    `printf '%s\\n' '${filePath}' >> .gitignore`,
    '# 3. Commit a value-free .env.example in its place.',
    '',
  ].join('\n')
  return {
    description: `Stop tracking ${filePath} and keep its values out of the repository.`,
    kind: 'snippet',
    language: 'sh',
    content,
    safetyNote:
      'Run this only after rotating the credentials. Untracking leaves every past commit intact, so treat the values as '
      + 'exposed until they are rotated; purging history is a separate, coordinated decision for a shared repository.',
  }
}

/** Package managers whose lockfile-refresh command is unambiguous. */
export type LockfileManager = 'pnpm' | 'yarn' | 'npm' | 'bun'

const LOCKFILE_REFRESH: Record<LockfileManager, { command: string; lockfile: string }> = {
  pnpm: { command: 'pnpm install --lockfile-only', lockfile: 'pnpm-lock.yaml' },
  yarn: { command: 'yarn install', lockfile: 'yarn.lock' },
  npm: { command: 'npm install --package-lock-only', lockfile: 'package-lock.json' },
  bun: { command: 'bun install', lockfile: 'bun.lock' },
}

/**
 * Lockfile refresh for the detected package manager. With no manager evidence
 * the snippet lists every command instead of picking one — a lockfile written
 * by the wrong manager is worse than no lockfile.
 */
export function lockfileRefreshFix(manager: LockfileManager | undefined): FindingFix {
  if (manager) {
    const { command, lockfile } = LOCKFILE_REFRESH[manager]
    return {
      description: `Generate and commit ${lockfile} with ${manager}.`,
      kind: 'snippet',
      language: 'sh',
      content: `${command}\ngit add ${lockfile}\n`,
      safetyNote:
        `Detected from this repository's own ${manager} configuration. Review the generated ${lockfile} before committing — `
        + 'it pins every transitive version resolved on the machine that ran the command.',
    }
  }
  const lines = (Object.keys(LOCKFILE_REFRESH) as LockfileManager[]).flatMap((name) => [
    `# ${name}`,
    `${LOCKFILE_REFRESH[name].command} && git add ${LOCKFILE_REFRESH[name].lockfile}`,
  ])
  return {
    description: 'Generate and commit a lockfile with the package manager your team uses.',
    kind: 'snippet',
    language: 'sh',
    content: `${lines.join('\n')}\n`,
    safetyNote:
      'No package-manager evidence was found in this repository, so every option is listed rather than one guessed. '
      + 'Run only the line for the manager your team uses — a lockfile from the wrong manager is worse than none.',
  }
}

export interface ReadmeStarterEvidence {
  projectName: string
  /** Install command for the detected package manager, when there is one. */
  installCommand?: string
}

/** Minimal README skeleton: the four sections the docs analyzer looks for. */
export function readmeStarterFix(evidence: ReadmeStarterEvidence): FindingFix {
  const quickStart = evidence.installCommand
    ? ['```sh', evidence.installCommand, '```']
    : ['Document the install and run commands for this project.']
  const content = [
    `# ${evidence.projectName}`,
    '',
    'One paragraph: what this project does and who it is for.',
    '',
    '## Quick start',
    '',
    ...quickStart,
    '',
    '## Environment variables',
    '',
    'Every variable this project reads, with a one-line purpose. Real values belong in a secret manager, never here.',
    '',
    '## Deployment',
    '',
    'How a change reaches production.',
    '',
  ].join('\n')
  return {
    description: 'Add a root README covering purpose, quick start, environment variables, and deployment.',
    kind: 'snippet',
    language: 'markdown',
    content,
    safetyNote:
      'A skeleton, not a description of this project — the prose is placeholder text that has to be replaced before it '
      + 'is worth committing.',
  }
}

export interface CiStarterEvidence {
  /** Package manager the workflow should install with. */
  manager: LockfileManager
  /** True when a lockfile is committed, which decides frozen vs plain install. */
  hasLockfile: boolean
  /** `packageManager` field in package.json, required by corepack for pnpm/yarn. */
  hasPackageManagerField: boolean
  /** package.json scripts that actually exist, in the order they should run. */
  scripts: string[]
}

const CI_SETUP_STEPS: Record<LockfileManager, (evidence: CiStarterEvidence) => string[] | undefined> = {
  npm: () => ['      - uses: actions/setup-node@v4', '        with:', '          node-version: lts/*'],
  pnpm: (evidence) => (evidence.hasPackageManagerField
    ? [
        '      - uses: actions/setup-node@v4',
        '        with:',
        '          node-version: lts/*',
        '      - run: corepack enable',
      ]
    : undefined),
  yarn: (evidence) => (evidence.hasPackageManagerField
    ? [
        '      - uses: actions/setup-node@v4',
        '        with:',
        '          node-version: lts/*',
        '      - run: corepack enable',
      ]
    : undefined),
  bun: () => ['      - uses: oven-sh/setup-bun@v2'],
}

const CI_INSTALL: Record<LockfileManager, (frozen: boolean) => string> = {
  npm: (frozen) => (frozen ? 'npm ci' : 'npm install'),
  pnpm: (frozen) => (frozen ? 'pnpm install --frozen-lockfile' : 'pnpm install'),
  yarn: (frozen) => (frozen ? 'yarn install --immutable' : 'yarn install'),
  bun: (frozen) => (frozen ? 'bun install --frozen-lockfile' : 'bun install'),
}

/**
 * Minimal GitHub Actions workflow. Emitted only for Node repositories whose
 * package.json names the scripts to run, so the workflow never invokes a script
 * that does not exist. Returns undefined when the setup steps would have to be
 * guessed (pnpm/yarn without a `packageManager` field for corepack).
 */
export function ciWorkflowFix(evidence: CiStarterEvidence): FindingFix | undefined {
  const setup = CI_SETUP_STEPS[evidence.manager](evidence)
  if (!setup || evidence.scripts.length === 0) return undefined
  const runner = evidence.manager === 'npm' ? 'npm run' : `${evidence.manager} run`
  const content = [
    'name: CI',
    'on:',
    '  push:',
    '    branches: [main]',
    '  pull_request:',
    'jobs:',
    '  verify:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v4',
    ...setup,
    `      - run: ${CI_INSTALL[evidence.manager](evidence.hasLockfile)}`,
    ...evidence.scripts.map((script) => `      - run: ${runner} ${script}`),
    '',
  ].join('\n')
  return {
    description: `Add .github/workflows/ci.yml running ${evidence.scripts.map((script) => `\`${script}\``).join(' and ')} on every push and pull request.`,
    kind: 'snippet',
    language: 'yaml',
    content,
    safetyNote:
      `The script names come from this repository's package.json; the action versions and \`lts/*\` Node version are `
      + 'defaults to pin to whatever your organization allows before merging.',
  }
}
