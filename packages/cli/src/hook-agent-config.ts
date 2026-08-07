import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { AgentSurface } from './hook-targets.js'

export type HookHandler = { type?: string; command?: string; args?: string[]; [key: string]: unknown }
export type HookGroup = { matcher?: string; hooks?: HookHandler[]; [key: string]: unknown }
export type HookDocument = { hooks?: Record<string, unknown>; [key: string]: unknown }

export const AGENT_EVENTS = ['UserPromptSubmit', 'PostToolUse', 'Stop'] as const
export type AgentEvent = typeof AGENT_EVENTS[number]

// The internal Stop review has a five-minute hard deadline. Keep the installed
// agent envelope wider so it can persist a failure result and clean private Git
// evidence before the host terminates the hook process.
const STOP_HOOK_TIMEOUT_SECONDS = 6 * 60

/** The host-owned settings file each agent surface reads its hooks from. */
export function agentSettingsPath(root: string, surface: AgentSurface): string {
  return join(root, surface === 'claude' ? '.claude/settings.json' : '.codex/hooks.json')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

export async function readHookDocument(path: string): Promise<HookDocument> {
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {}
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch (error) {
    throw new Error(`refusing to overwrite invalid JSON in ${path}: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!isRecord(parsed)) throw new Error(`refusing to overwrite ${path}: top-level JSON must be an object`)
  if (parsed.hooks !== undefined && !isRecord(parsed.hooks)) {
    throw new Error(`refusing to overwrite ${path}: hooks must be an object`)
  }
  return parsed as HookDocument
}

export function eventGroups(doc: HookDocument, path: string, event: string): HookGroup[] {
  doc.hooks ??= {}
  const value = doc.hooks[event]
  if (value === undefined) {
    const groups: HookGroup[] = []
    doc.hooks[event] = groups
    return groups
  }
  if (!Array.isArray(value) || value.some((group) => !isRecord(group))) {
    throw new Error(`refusing to overwrite ${path}: hooks.${event} must be an array of objects`)
  }
  for (const group of value as HookGroup[]) {
    if (group.hooks !== undefined && (!Array.isArray(group.hooks) || group.hooks.some((handler) => !isRecord(handler)))) {
      throw new Error(`refusing to overwrite ${path}: hooks.${event}[].hooks must be an array of objects`)
    }
  }
  return value as HookGroup[]
}

export function isCodeTrussHandler(handler: HookHandler): boolean {
  return [handler.command, ...(handler.args ?? [])].some((value) => typeof value === 'string' && value.includes('.codetruss/hooks/agent.cjs'))
}

export function removeCodeTrussHandlers(groups: HookGroup[]): void {
  for (let index = groups.length - 1; index >= 0; index--) {
    const group = groups[index]
    if (!Array.isArray(group.hooks)) continue
    group.hooks = group.hooks.filter((handler) => !isCodeTrussHandler(handler))
    if (group.hooks.length === 0) groups.splice(index, 1)
  }
}

function agentCommand(surface: AgentSurface): HookHandler {
  if (surface === 'claude') {
    return {
      command: 'node',
      args: ['${CLAUDE_PROJECT_DIR}/.codetruss/hooks/agent.cjs', 'claude'],
    }
  }
  return {
    command: 'node "$(git -c core.longpaths=true rev-parse --show-toplevel)/.codetruss/hooks/agent.cjs" codex',
    commandWindows: "$root = git -c core.longpaths=true rev-parse --show-toplevel; if ($LASTEXITCODE -eq 0) { node (Join-Path $root '.codetruss/hooks/agent.cjs') codex }",
  }
}

/** The group matcher CodeTruss installs alongside an event's handler, if any. */
export function agentEventMatcher(event: AgentEvent): string | undefined {
  return event === 'PostToolUse' ? 'Edit|Write' : undefined
}

export function agentHandler(surface: AgentSurface, event: AgentEvent): HookHandler {
  const timeout = event === 'PostToolUse' ? 10 : event === 'UserPromptSubmit' ? 60 : STOP_HOOK_TIMEOUT_SECONDS
  const statusMessage = event === 'PostToolUse'
    ? 'Checking scope with CodeTruss'
    : event === 'UserPromptSubmit'
      ? 'Capturing CodeTruss turn baseline'
      : 'Writing CodeTruss review receipt'
  return { type: 'command', ...agentCommand(surface), timeout, statusMessage }
}
