import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { LocalCommandError, runLocalCommand } from '../src/local-command.js'

const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

describe('local provider process isolation', () => {
  it('delivers prompt bytes over stdin and returns bounded output', async () => {
    const cwd = await temporaryDirectory()
    const input = 'TASK_AND_DIFF_STDIN_MARKER'

    const result = await runLocalCommand({
      command: process.execPath,
      args: ['-e', 'process.stdin.pipe(process.stdout)'],
      cwd,
      input,
      timeoutMs: 2_000,
      maxOutputBytes: 1_000,
    })

    expect(result).toMatchObject({ stdout: input, stderr: '', exitCode: 0, signal: null })
  })

  it('uses an explicit minimal environment instead of leaking parent secrets', async () => {
    const cwd = await temporaryDirectory()
    process.env.CODETRUSS_LOCAL_COMMAND_SECRET_MARKER = 'must-not-leak'
    try {
      const result = await runLocalCommand({
        command: process.execPath,
        args: ['-e', 'process.stdout.write(JSON.stringify(process.env))'],
        cwd,
        env: { PATH: process.env.PATH, CODETRUSS_ALLOWED_MARKER: 'allowed' },
        timeoutMs: 2_000,
      })

      const childEnvironment = JSON.parse(result.stdout) as Record<string, string>
      expect(childEnvironment.CODETRUSS_ALLOWED_MARKER).toBe('allowed')
      expect(childEnvironment.CODETRUSS_LOCAL_COMMAND_SECRET_MARKER).toBeUndefined()
    } finally {
      delete process.env.CODETRUSS_LOCAL_COMMAND_SECRET_MARKER
    }
  })

  it('terminates a command that exceeds its deadline', async () => {
    const cwd = await temporaryDirectory()

    const failure = await runLocalCommand({
      command: process.execPath,
      args: ['-e', 'setInterval(() => {}, 1_000)'],
      cwd,
      timeoutMs: 40,
    }).catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(LocalCommandError)
    expect(failure).toMatchObject({ reason: 'timeout', timeoutMs: 40 })
  })

  it('terminates a command that exceeds the combined output cap', async () => {
    const cwd = await temporaryDirectory()

    const failure = await runLocalCommand({
      command: process.execPath,
      args: ['-e', 'process.stdout.write("x".repeat(1_024)); setInterval(() => {}, 1_000)'],
      cwd,
      timeoutMs: 2_000,
      maxOutputBytes: 64,
    }).catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(LocalCommandError)
    expect(failure).toMatchObject({ reason: 'output-limit' })
  })

  it('returns the provider result when an escaped helper holds its pipes', async () => {
    const cwd = await temporaryDirectory()
    const descendantScript = join(cwd, 'holder-descendant.cjs')
    const providerScript = join(cwd, 'holder-provider.cjs')
    const sentinel = join(cwd, 'holder-descendant.keepalive')
    await writeFile(sentinel, '')
    // A provider that forks a helper it does not wait for: the helper escapes
    // cleanup on every platform — POSIX because `detached` makes it its own
    // session leader, Windows because it outlives the leader taskkill would
    // have had to enumerate it from — and keeps the inherited pipes, and
    // therefore `close`, open. The review the provider already printed must
    // still be returned rather than discarded as a deadline failure. Cleanup
    // never signals the recorded pid (Windows recycles a freed pid within
    // milliseconds); the helper exits once the sentinel disappears, and it
    // runs outside the temporary directory so the afterEach can remove it.
    await writeFile(descendantScript, [
      "const { existsSync } = require('node:fs')",
      `const sentinel = ${JSON.stringify(sentinel)}`,
      'setInterval(() => { if (!existsSync(sentinel)) process.exit(0) }, 100)',
    ].join('\n'))
    await writeFile(providerScript, [
      "const { spawn } = require('node:child_process')",
      `spawn(process.execPath, [${JSON.stringify(descendantScript)}], { cwd: ${JSON.stringify(tmpdir())}, detached: true, stdio: ['ignore', 'inherit', 'inherit'] }).unref()`,
      "process.stdout.write('REVIEW_COMPLETE')",
    ].join(';'))

    try {
      // The deadline outlasts this test's own budget on purpose: a call that
      // went back to waiting for `close` fails on the Vitest timeout rather
      // than passing slowly.
      const result = await runLocalCommand({
        command: process.execPath,
        args: [providerScript],
        cwd,
        timeoutMs: 60_000,
      })

      expect(result).toMatchObject({ stdout: 'REVIEW_COMPLETE', exitCode: 0, signal: null })
    } finally {
      await rm(sentinel, { force: true })
    }
  }, 20_000)

  it.runIf(process.platform !== 'win32')('cleans up descendants after the command exits', async () => {
    const cwd = await temporaryDirectory()
    const pidFile = join(cwd, 'descendant.pid')
    const script = [
      "const { spawn } = require('node:child_process')",
      "const { writeFileSync } = require('node:fs')",
      "const descendant = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })",
      'descendant.unref()',
      `writeFileSync(${JSON.stringify(pidFile)}, String(descendant.pid))`,
    ].join(';')
    let descendantPid: number | undefined

    try {
      const result = await runLocalCommand({
        command: process.execPath,
        args: ['-e', script],
        cwd,
        timeoutMs: 2_000,
      })
      expect(result.exitCode).toBe(0)
      descendantPid = Number(await readFile(pidFile, 'utf8'))
      expect(Number.isSafeInteger(descendantPid)).toBe(true)
      await expectProcessToExit(descendantPid)
    } finally {
      if (descendantPid !== undefined && processExists(descendantPid)) {
        try { process.kill(descendantPid, 'SIGKILL') } catch { /* already gone */ }
      }
    }
  })
})

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'codetruss-local-command-test-'))
  temporaryDirectories.push(directory)
  return directory
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH'
  }
}

async function expectProcessToExit(pid: number): Promise<void> {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (!processExists(pid)) return
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error(`descendant process ${pid} was not terminated`)
}
