/** The hook surfaces a user can install, inspect, or remove. */
export type HookTarget = 'pre-commit' | 'claude' | 'codex'

/** The two agent surfaces; `pre-commit` is a shell hook and handled separately. */
export type AgentSurface = Exclude<HookTarget, 'pre-commit'>

export function parseTargets(target: string): HookTarget[] {
  const valid = new Set(['pre-commit', 'claude', 'codex', 'all'])
  if (!valid.has(target)) throw new Error(`unknown hook target ${target}; expected pre-commit, claude, codex, or all`)
  return target === 'all' ? ['pre-commit', 'claude', 'codex'] : [target as HookTarget]
}
