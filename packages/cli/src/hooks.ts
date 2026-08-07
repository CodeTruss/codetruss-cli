import { readFile, rm, writeFile } from 'node:fs/promises'
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
  removeCodeTrussHandlers,
} from './hook-agent-config.js'
import { AGENT_RUNNER } from './hook-agent-runner.js'
import { inspectHookDoctor, type HookDoctorResult } from './hook-doctor.js'
import { executablePath } from './hook-executable.js'
import {
  BEGIN_MARKER,
  effectivePreCommitPath,
  preCommitBlock,
  stripCodeTrussPreCommit,
} from './hook-pre-commit.js'
import { parseTargets, type AgentSurface, type HookTarget } from './hook-targets.js'
import { commitPlannedWrites, mergePlannedWrites, plannedWrite, type HookInstallPlan } from './hook-writes.js'
import { verifyCommandTrustStatus } from './verify-trust.js'

export { CODETRUSS_PRE_COMMIT_ENV } from './hook-pre-commit.js'
export { installedCliVersion } from './hook-executable.js'
export {
  inspectHookDoctor,
  inspectLocalHookHealth,
  type HookDoctorCheck,
  type HookDoctorResult,
  type HookHealthStatus,
  type LocalHookHealth,
} from './hook-doctor.js'

async function planAgentHook(root: string, surface: AgentSurface): Promise<HookInstallPlan> {
  const path = agentSettingsPath(root, surface)
  const doc = await readHookDocument(path)
  for (const event of AGENT_EVENTS) {
    const groups = eventGroups(doc, path, event)
    removeCodeTrussHandlers(groups)
    const matcher = agentEventMatcher(event)
    groups.push({
      ...(matcher === undefined ? {} : { matcher }),
      hooks: [agentHandler(surface, event)],
    })
  }
  const runnerPath = join(root, '.codetruss', 'hooks', 'agent.cjs')
  return {
    writes: [
      plannedWrite(runnerPath, AGENT_RUNNER, 0o644),
      plannedWrite(path, `${JSON.stringify(doc, null, 2)}\n`, 0o600),
    ],
    installedPaths: [path],
  }
}

async function planPreCommit(root: string): Promise<HookInstallPlan> {
  const path = effectivePreCommitPath(root)
  let existing = ''
  try {
    existing = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  existing = stripCodeTrussPreCommit(existing)
  if (existing) {
    const shebang = existing.split(/\r?\n/, 1)[0]
    if (!/^#!.*\b(?:ba|da|k|z)?sh(?:\s|$)/.test(shebang)) {
      throw new Error(`existing ${path} is not a POSIX shell hook and was left unchanged; invoke "codetruss review --staged --task pre-commit" from that hook or your hook manager`)
    }
  } else {
    existing = '#!/bin/sh\n'
  }
  // Normalize only the separator we own. This preserves user hook bytes while
  // making repeated installation byte-for-byte idempotent.
  existing = `${existing.replace(/(?:\r?\n)+$/g, '')}\n`
  existing += `\n${preCommitBlock()}\n`
  return {
    writes: [plannedWrite(path, existing, 0o755, 0o755)],
    installedPaths: [path],
  }
}

async function assertHookPolicyReady(root: string, targets: HookTarget[]): Promise<void> {
  const config = await loadConfig(root)
  if (targets.some((target) => target === 'claude' || target === 'codex') && config.allow.length === 0) {
    throw new Error('agent hooks require at least one allow glob in .codetruss.yml; run codetruss init, define the intended task surface, then install again')
  }
  if (config.verify.length) {
    const trust = await verifyCommandTrustStatus(root, config.verify)
    if (!trust.trusted) {
      throw new Error(`hooks require trusted repository verification commands (${trust.hash.slice(0, 12)}); inspect them and run codetruss verify-policy trust`)
    }
  }
}

export async function installHooks(root: string, target: string): Promise<void> {
  const targets = parseTargets(target)
  await assertHookPolicyReady(root, targets)
  if (!await executablePath(root)) {
    throw new Error('automatic hooks require a persistent CodeTruss CLI installed in this repository or on PATH')
  }
  // Build and validate every mutation before publishing any one of them. This
  // keeps `all` from leaving a half-installed hook set when a later user-owned
  // JSON file is malformed or unwritable.
  const plans = await Promise.all(targets.map((name) => (
    name === 'pre-commit' ? planPreCommit(root) : planAgentHook(root, name)
  )))
  const plan = mergePlannedWrites(plans)
  await commitPlannedWrites(plan.writes)
  for (const path of plan.installedPaths) process.stdout.write(`installed ${path}\n`)
}

async function uninstallAgentHook(root: string, surface: AgentSurface): Promise<void> {
  const path = agentSettingsPath(root, surface)
  const doc = await readHookDocument(path)
  let changed = false
  for (const event of AGENT_EVENTS) {
    const groups = eventGroups(doc, path, event)
    const before = JSON.stringify(groups)
    removeCodeTrussHandlers(groups)
    if (before !== JSON.stringify(groups)) changed = true
    if (groups.length === 0) delete doc.hooks?.[event]
  }
  if (changed) await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`, 'utf8')
  process.stdout.write(`${changed ? 'uninstalled' : 'not installed'} ${path}\n`)
}

async function uninstallPreCommit(root: string): Promise<void> {
  const path = effectivePreCommitPath(root)
  let existing: string
  try {
    existing = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      process.stdout.write(`not installed ${path}\n`)
      return
    }
    throw error
  }
  const stripped = stripCodeTrussPreCommit(existing)
  if (stripped === existing) {
    process.stdout.write(`not installed ${path}\n`)
    return
  }
  if (/^#![^\n]+\n\s*$/.test(stripped)) await rm(path, { force: true })
  else await writeFile(path, stripped, 'utf8')
  process.stdout.write(`uninstalled ${path}\n`)
}

export async function uninstallHooks(root: string, target: string): Promise<void> {
  for (const name of parseTargets(target)) {
    if (name === 'pre-commit') await uninstallPreCommit(root)
    else await uninstallAgentHook(root, name)
  }
}

async function agentInstalled(root: string, surface: AgentSurface): Promise<boolean> {
  const path = agentSettingsPath(root, surface)
  const doc = await readHookDocument(path)
  return AGENT_EVENTS.every((event) => eventGroups(doc, path, event).some((group) => group.hooks?.some(isCodeTrussHandler)))
}

export async function doctorHooks(root: string, target: string): Promise<HookDoctorResult> {
  const result = await inspectHookDoctor(root, target)
  for (const check of result.checks) {
    process.stdout.write(`${check.level.toUpperCase()}\t${check.target}\t${check.message}${check.path ? `\t${check.path}` : ''}\n`)
  }
  const errors = result.checks.filter((check) => check.level === 'error').length
  const warnings = result.checks.filter((check) => check.level === 'warning').length
  process.stdout.write(`doctor\t${result.ok ? 'healthy' : 'unhealthy'}\t${errors} error(s), ${warnings} warning(s)\n`)
  return result
}

export async function hookStatus(root: string, target: string): Promise<void> {
  for (const name of parseTargets(target)) {
    let installed: boolean
    let path: string
    if (name === 'pre-commit') {
      path = effectivePreCommitPath(root)
      installed = await readFile(path, 'utf8').then((text) => text.includes(BEGIN_MARKER), () => false)
    } else {
      path = agentSettingsPath(root, name)
      installed = await agentInstalled(root, name)
    }
    process.stdout.write(`${installed ? 'installed' : 'not installed'}\t${name}\t${path}\n`)
  }
}
