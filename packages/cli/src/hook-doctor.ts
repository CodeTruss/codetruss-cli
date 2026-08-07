import { lstat, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { loadConfig } from './config.js'
import {
  AGENT_EVENTS,
  agentEventMatcher,
  agentHandler,
  agentSettingsPath,
  eventGroups,
  isCodeTrussHandler,
  readHookDocument,
  type HookDocument,
  type HookGroup,
  type HookHandler,
} from './hook-agent-config.js'
import { AGENT_RUNNER } from './hook-agent-runner.js'
import { executablePath, installedCliVersion } from './hook-executable.js'
import { BEGIN_MARKER, END_MARKER, effectivePreCommitPath, preCommitBlock } from './hook-pre-commit.js'
import { parseTargets, type AgentSurface, type HookTarget } from './hook-targets.js'
import { CLI_VERSION } from './version.js'
import { verifyCommandTrustStatus } from './verify-trust.js'

const SUPPORTS_POSIX_FILE_MODES = process.platform !== 'win32'

export interface HookDoctorCheck {
  level: 'ok' | 'warning' | 'error'
  target: HookTarget | 'config' | 'runtime' | 'agent-runtime'
  message: string
  path?: string
}

export interface HookDoctorResult {
  ok: boolean
  checks: HookDoctorCheck[]
}

export type HookHealthStatus = 'not_installed' | 'healthy' | 'warning' | 'unhealthy'

export interface LocalHookHealth {
  preCommit: HookHealthStatus
  claude: HookHealthStatus
  codex: HookHealthStatus
}

type AddCheck = (check: HookDoctorCheck) => void

/**
 * The hooks invoke `codetruss` by name, so they run whatever PATH resolves —
 * which is not always what was just installed. A stale binary earlier in PATH
 * silently shadows the new one, and the installer's own "Ready" message used to
 * hide it. Reported as a warning: the hooks still work, they just are not this
 * version. Determined by manifest version, so a repository-local install of the
 * same version is not mistaken for a shadow.
 */
async function inspectExecutableShadow(executable: string, add: AddCheck): Promise<void> {
  const resolved = await installedCliVersion(executable)
  if (!resolved || resolved === CLI_VERSION) return
  add({
    level: 'warning',
    target: 'runtime',
    message: `installed hooks resolve codetruss ${resolved}, but this CLI is ${CLI_VERSION}; put the intended install first on PATH or remove the older one`,
    path: executable,
  })
}

const AGENT_HANDLER_FIELDS = ['type', 'command', 'args', 'commandWindows', 'timeout', 'statusMessage'] as const

/**
 * Which fields of an installed agent handler no longer match what this CLI
 * would write. Doctor always compared handlers exactly but reported only that
 * they "differ", which reads the same for a config installed several versions
 * ago as for a deliberate hand-edit. Field names only: enough to diagnose,
 * without putting handler command text in the message.
 */
function agentHandlerDrift(handler: HookHandler, expected: HookHandler): string[] {
  return AGENT_HANDLER_FIELDS.filter((field) => (
    JSON.stringify(handler[field] ?? null) !== JSON.stringify(expected[field] ?? null)
  ))
}

async function inspectAgentHook(root: string, surface: AgentSurface, add: AddCheck): Promise<void> {
  const path = agentSettingsPath(root, surface)
  let doc: HookDocument
  try {
    doc = await readHookDocument(path)
  } catch (error) {
    add({ level: 'error', target: surface, message: error instanceof Error ? error.message : String(error), path })
    return
  }
  for (const event of AGENT_EVENTS) {
    let groups: HookGroup[]
    try {
      groups = eventGroups(doc, path, event)
    } catch (error) {
      add({ level: 'error', target: surface, message: error instanceof Error ? error.message : String(error), path })
      return
    }
    const installed = groups.flatMap((group) => (group.hooks ?? []).map((handler) => ({ group, handler })))
      .filter(({ handler }) => isCodeTrussHandler(handler))
    if (installed.length !== 1) {
      add({
        level: 'error',
        target: surface,
        message: `${event} must contain exactly one CodeTruss handler (found ${installed.length})`,
        path,
      })
      continue
    }
    const expected = agentHandler(surface, event)
    const drift = agentHandlerDrift(installed[0].handler, expected)
    if (installed[0].group.matcher !== agentEventMatcher(event)) drift.push('matcher')
    if (drift.length) {
      const detail = `(${drift.join(', ')}); run codetruss hooks install ${surface} to refresh it`
      add({ level: 'error', target: surface, message: `${event} handler differs from the current safe installation ${detail}`, path })
      continue
    }
    add({ level: 'ok', target: surface, message: `${event} handler is current`, path })
  }
  try {
    const metadata = await lstat(path)
    if (SUPPORTS_POSIX_FILE_MODES && (metadata.mode & 0o022) !== 0) {
      add({ level: 'error', target: surface, message: 'hook configuration is writable by group or other users', path })
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      add({ level: 'error', target: surface, message: error instanceof Error ? error.message : String(error), path })
    }
  }
}

async function inspectRunner(root: string, add: AddCheck): Promise<void> {
  const path = join(root, '.codetruss', 'hooks', 'agent.cjs')
  try {
    const [contents, metadata] = await Promise.all([readFile(path, 'utf8'), lstat(path)])
    if (!metadata.isFile()) {
      add({ level: 'error', target: 'agent-runtime', message: 'agent hook runner is not a regular file', path })
    } else if (contents !== AGENT_RUNNER) {
      add({ level: 'error', target: 'agent-runtime', message: 'agent hook runner differs from this CLI version; reinstall hooks', path })
    } else if (SUPPORTS_POSIX_FILE_MODES && (metadata.mode & 0o022) !== 0) {
      add({ level: 'error', target: 'agent-runtime', message: 'agent hook runner is writable by group or other users', path })
    } else {
      add({
        level: 'ok',
        target: 'agent-runtime',
        message: SUPPORTS_POSIX_FILE_MODES
          ? 'agent hook runner is current and owner-controlled'
          : 'agent hook runner is current; POSIX permission checks do not apply on Windows',
        path,
      })
    }
  } catch (error) {
    add({
      level: 'error',
      target: 'agent-runtime',
      message: (error as NodeJS.ErrnoException).code === 'ENOENT'
        ? 'agent hook runner is missing; reinstall hooks'
        : error instanceof Error ? error.message : String(error),
      path,
    })
  }
}

async function inspectPreCommit(root: string, add: AddCheck): Promise<void> {
  const path = effectivePreCommitPath(root)
  try {
    const [contents, metadata] = await Promise.all([readFile(path, 'utf8'), lstat(path)])
    const beginCount = contents.split(BEGIN_MARKER).length - 1
    const endCount = contents.split(END_MARKER).length - 1
    const begin = contents.indexOf(BEGIN_MARKER)
    const end = contents.indexOf(END_MARKER, begin) + END_MARKER.length
    if (beginCount !== 1 || endCount !== 1 || begin < 0 || contents.slice(begin, end) !== preCommitBlock()) {
      add({ level: 'error', target: 'pre-commit', message: 'installed block is missing, duplicated, or stale; reinstall hooks', path })
    } else {
      add({ level: 'ok', target: 'pre-commit', message: 'staged-review block is current', path })
    }
    if (!SUPPORTS_POSIX_FILE_MODES) {
      add({ level: 'ok', target: 'pre-commit', message: 'hook file is present; POSIX permission checks do not apply on Windows', path })
    } else if ((metadata.mode & 0o100) === 0) {
      add({ level: 'error', target: 'pre-commit', message: 'hook is not executable by its owner', path })
    } else if ((metadata.mode & 0o022) !== 0) {
      add({ level: 'error', target: 'pre-commit', message: 'hook is writable by group or other users', path })
    } else {
      add({ level: 'ok', target: 'pre-commit', message: 'hook permissions are owner-controlled and executable', path })
    }
  } catch (error) {
    add({
      level: 'error',
      target: 'pre-commit',
      message: (error as NodeJS.ErrnoException).code === 'ENOENT'
        ? 'hook is not installed'
        : error instanceof Error ? error.message : String(error),
      path,
    })
  }
}

export async function inspectHookDoctor(root: string, target: string): Promise<HookDoctorResult> {
  const targets = parseTargets(target)
  const checks: HookDoctorCheck[] = []
  const add: AddCheck = (check) => checks.push(check)
  const agentTargets = targets.filter((name): name is AgentSurface => name !== 'pre-commit')
  try {
    const config = await loadConfig(root)
    if (config.verify.length) {
      const trust = await verifyCommandTrustStatus(root, config.verify)
      add({
        level: trust.trusted ? 'ok' : 'error',
        target: 'config',
        message: trust.trusted
          ? `repository verification commands are trusted (${trust.hash.slice(0, 12)})`
          : `repository verification commands are untrusted (${trust.hash.slice(0, 12)}); inspect them and run codetruss verify-policy trust`,
        path: join(root, '.codetruss.yml'),
      })
    }
  } catch (error) {
    add({ level: 'error', target: 'config', message: error instanceof Error ? error.message : String(error), path: join(root, '.codetruss.yml') })
  }
  if (agentTargets.length) {
    try {
      const config = await loadConfig(root)
      if (config.allow.length) {
        add({ level: 'ok', target: 'config', message: `${config.allow.length} allowed task-scope glob${config.allow.length === 1 ? '' : 's'} configured`, path: join(root, '.codetruss.yml') })
      } else {
        add({ level: 'error', target: 'config', message: 'agent hooks require at least one allow glob in .codetruss.yml', path: join(root, '.codetruss.yml') })
      }
    } catch (error) {
      add({ level: 'error', target: 'config', message: error instanceof Error ? error.message : String(error), path: join(root, '.codetruss.yml') })
    }
    await inspectRunner(root, add)
  }
  const cliPath = await executablePath(root)
  if (cliPath) {
    add({ level: 'ok', target: 'runtime', message: 'CodeTruss CLI is resolvable by installed hooks', path: cliPath })
    await inspectExecutableShadow(cliPath, add)
  } else add({ level: 'error', target: 'runtime', message: 'CodeTruss CLI is not available locally or on PATH' })
  for (const name of targets) {
    if (name === 'pre-commit') await inspectPreCommit(root, add)
    else {
      await inspectAgentHook(root, name, add)
      if (name === 'codex') {
        add({
          level: 'warning',
          target: 'codex',
          message: 'hook trust cannot be verified here; open /hooks in Codex and trust this exact project hook. New or changed hook definitions require review again',
          path: join(root, '.codex', 'hooks.json'),
        })
      }
    }
  }
  const errors = checks.filter((check) => check.level === 'error').length
  return { ok: errors === 0, checks }
}

async function hookInstallations(root: string): Promise<Record<HookTarget, boolean>> {
  const agentPresent = async (surface: AgentSurface): Promise<boolean> => (
    readFile(agentSettingsPath(root, surface), 'utf8')
      .then((text) => text.includes('.codetruss/hooks/agent.cjs'), () => false)
  )
  return {
    'pre-commit': await readFile(effectivePreCommitPath(root), 'utf8')
      .then((text) => text.includes(BEGIN_MARKER), () => false),
    claude: await agentPresent('claude'),
    codex: await agentPresent('codex'),
  }
}

/** Privacy-safe health summary: no hook path, command, or diagnostic text leaves this function. */
export async function inspectLocalHookHealth(root: string): Promise<LocalHookHealth> {
  const [installed, preCommitDoctor, claudeDoctor, codexDoctor] = await Promise.all([
    hookInstallations(root),
    inspectHookDoctor(root, 'pre-commit'),
    inspectHookDoctor(root, 'claude'),
    inspectHookDoctor(root, 'codex'),
  ])
  const doctors: Record<HookTarget, HookDoctorResult> = {
    'pre-commit': preCommitDoctor,
    claude: claudeDoctor,
    codex: codexDoctor,
  }
  const status = (target: HookTarget): HookHealthStatus => {
    if (!installed[target]) return 'not_installed'
    const relevant = doctors[target].checks.filter((check) => (
      check.target === target
      || check.target === 'runtime'
      || check.target === 'agent-runtime'
      || check.target === 'config'
    ))
    if (relevant.some((check) => check.level === 'error')) return 'unhealthy'
    if (relevant.some((check) => check.level === 'warning')) return 'warning'
    return 'healthy'
  }
  return {
    preCommit: status('pre-commit'),
    claude: status('claude'),
    codex: status('codex'),
  }
}
