/**
 * The `.codetruss/hooks/agent.cjs` payload installed into a repository.
 *
 * This is a standalone CommonJS program executed by the host agent, not by this
 * CLI, so it is kept verbatim in one place: `inspectRunner` compares the file on
 * disk against this exact string to detect drift, which means any incidental
 * edit here is a behaviour change for every installed repository.
 */
export const AGENT_RUNNER = `'use strict'
const { existsSync } = require('node:fs')
const { execFileSync, spawnSync } = require('node:child_process')
const { join } = require('node:path')

const surface = process.argv[2]
const maxInputBytes = 16 * 1024 * 1024
if (surface !== 'claude' && surface !== 'codex') {
  process.stderr.write('codetruss hook: expected claude or codex\\n')
  process.exit(3)
}

function safeFailure(input, message) {
  let event
  let stopHookActive = false
  const textInput = input.toString('utf8')
  try {
    const parsed = JSON.parse(textInput)
    event = parsed.hook_event_name
    stopHookActive = parsed.stop_hook_active === true
  } catch {
    const prefix = textInput.slice(0, 64 * 1024)
    event = /"hook_event_name"\\s*:\\s*"([^"]+)"/.exec(prefix)?.[1]
    stopHookActive = /"stop_hook_active"\\s*:\\s*true/.test(prefix)
  }
  const text = ('CodeTruss hook failed safely: ' + message).slice(0, 9000)
  if (event === 'UserPromptSubmit' || (event === 'Stop' && !stopHookActive)) {
    return { decision: 'block', reason: text }
  }
  return { systemMessage: text }
}

const chunks = []
let inputBytes = 0
let tooLarge = false
process.stdin.on('data', (value) => {
  const chunk = Buffer.from(value)
  inputBytes += chunk.length
  if (inputBytes > maxInputBytes) tooLarge = true
  else chunks.push(chunk)
})
process.stdin.on('end', () => {
  const input = Buffer.concat(chunks)
  if (tooLarge) {
    process.stdout.write(JSON.stringify(safeFailure(input, 'hook input exceeded 16 MiB')) + '\\n')
    process.exit(0)
  }
  let root
  try {
    root = execFileSync('git', ['-c', 'core.longpaths=true', 'rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim()
  } catch {
    process.stdout.write(JSON.stringify(safeFailure(input, 'could not resolve the Git repository root')) + '\\n')
    process.exit(0)
  }
  const local = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
  const command = existsSync(local) ? local : 'codetruss'
  const result = spawnSync(command, ['hooks', 'dispatch', surface], {
    cwd: root,
    input,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    maxBuffer: 64 * 1024,
  })
  if (result.error || result.status !== 0) {
    const detail = result.error ? result.error.message : (result.stderr || 'dispatch exited with status ' + String(result.status)).trim()
    process.stdout.write(JSON.stringify(safeFailure(input, detail)) + '\\n')
    process.exit(0)
  }
  if (result.stderr) process.stderr.write(result.stderr)
  if (result.stdout) process.stdout.write(result.stdout)
  process.exit(0)
})
`
