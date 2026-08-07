import { spawn, spawnSync, type ChildProcess } from 'node:child_process'

export const LOCAL_COMMAND_MAX_OUTPUT_BYTES = 2_000_000

/**
 * How long a call keeps capturing after the provider's own process has exited.
 *
 * Mirrors the verification grace in git.ts, for the same reason: a provider can
 * leave a helper holding the stdio pipes it inherited, `close` waits on those
 * pipes, and a helper that escaped the process group cannot always be
 * terminated (see terminateProcessTree). Without a bound, a review the provider
 * already finished and printed would be discarded as a timeout.
 */
const LOCAL_COMMAND_ESCAPED_OUTPUT_GRACE_MS = 2_000

export type LocalCommandFailureReason = 'spawn' | 'timeout' | 'output-limit'

export class LocalCommandError extends Error {
  constructor(
    readonly command: string,
    readonly reason: LocalCommandFailureReason,
    readonly timeoutMs?: number,
  ) {
    const detail = reason === 'timeout' && timeoutMs !== undefined
      ? ` timed out after ${timeoutMs}ms`
      : reason === 'output-limit'
        ? ' exceeded the output limit'
        : ' could not be started'
    super(`${command}${detail}`)
    this.name = 'LocalCommandError'
  }
}

export interface LocalCommandRequest {
  command: string
  args: string[]
  cwd: string
  input?: string
  env?: Record<string, string | undefined>
  timeoutMs: number
  maxOutputBytes?: number
}

export interface LocalCommandResult {
  stdout: string
  stderr: string
  exitCode: number | null
  signal: NodeJS.Signals | null
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

function signalProcessGroup(pid: number, signal: NodeJS.Signals): boolean {
  try {
    process.kill(-pid, signal)
    return true
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ESRCH') return false
    return code === 'EPERM'
  }
}

async function terminateProcessTree(child: ChildProcess): Promise<void> {
  const pid = child.pid
  if (pid === undefined) return
  if (process.platform === 'win32') {
    // taskkill /t enumerates the tree from the leader pid, so once the leader
    // has exited it cannot reach anything — and Windows recycles freed pids
    // within milliseconds, so addressing one can force-kill an unrelated
    // process. The liveness check uses our own process handle and cannot be
    // misdirected; a leader exiting between this check and taskkill's own
    // snapshot is the same narrow race every taskkill user carries.
    //
    // KNOWN LIMIT — a descendant that outlives the leader is not reaped here,
    // and cannot be: Windows leaves a dead parent id behind rather than
    // reparenting, so the chain from this pid to that descendant no longer
    // exists to walk, and matching on the stale parent id would be
    // pid-recycling roulette by another name. Containment that survives
    // ancestor death needs a kernel job object (KILL_ON_JOB_CLOSE), for which
    // Node has no API and this CLI ships no native addon or helper binary. The
    // escape is bounded instead of prevented — see
    // LOCAL_COMMAND_ESCAPED_OUTPUT_GRACE_MS.
    if (child.exitCode !== null || child.signalCode !== null) return
    spawnSync('taskkill', ['/pid', String(pid), '/t', '/f'], {
      stdio: 'ignore',
      timeout: 2_000,
      windowsHide: true,
    })
    return
  }

  if (!signalProcessGroup(pid, 'SIGTERM')) return
  await delay(150)
  signalProcessGroup(pid, 'SIGKILL')
}

/**
 * Run an untrusted local provider without a shell. The caller supplies prompt
 * bytes through stdin; the command line contains provider options only.
 */
export function runLocalCommand(request: LocalCommandRequest): Promise<LocalCommandResult> {
  const maxOutputBytes = request.maxOutputBytes ?? LOCAL_COMMAND_MAX_OUTPUT_BYTES
  if (!Number.isSafeInteger(request.timeoutMs) || request.timeoutMs <= 0) {
    throw new Error('local command timeoutMs must be a positive integer')
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error('local command maxOutputBytes must be a positive integer')
  }

  return new Promise((resolve, reject) => {
    const child = spawn(request.command, request.args, {
      cwd: request.cwd,
      detached: process.platform !== 'win32',
      env: request.env === undefined ? process.env : request.env as NodeJS.ProcessEnv,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    let outputBytes = 0
    let failure: LocalCommandError | undefined
    let settled = false
    let cleanupPromise: Promise<void> | undefined
    let escapeTimer: NodeJS.Timeout | undefined

    const cleanup = () => {
      cleanupPromise ??= terminateProcessTree(child)
      return cleanupPromise
    }
    const succeed = (exitCode: number | null, signal: NodeJS.Signals | null) => {
      clearTimeout(timer)
      clearTimeout(escapeTimer)
      child.stdin.destroy()
      void cleanup().finally(() => {
        child.stdout.destroy()
        child.stderr.destroy()
        child.unref()
        if (settled) return
        settled = true
        if (failure) {
          reject(failure)
          return
        }
        resolve({
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
          exitCode,
          signal,
        })
      })
    }
    const fail = (reason: LocalCommandFailureReason) => {
      if (failure) return
      failure = new LocalCommandError(request.command, reason, reason === 'timeout' ? request.timeoutMs : undefined)
      clearTimeout(timer)
      clearTimeout(escapeTimer)
      child.stdin.destroy()
      void cleanup().finally(() => {
        child.stdout.destroy()
        child.stderr.destroy()
        child.unref()
        if (settled) return
        settled = true
        reject(failure)
      })
    }
    const collect = (target: Buffer[], chunk: Buffer | string) => {
      if (failure) return
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      outputBytes += buffer.byteLength
      if (outputBytes > maxOutputBytes) {
        fail('output-limit')
        return
      }
      target.push(buffer)
    }

    child.stdout.on('data', (chunk: Buffer | string) => collect(stdout, chunk))
    child.stderr.on('data', (chunk: Buffer | string) => collect(stderr, chunk))
    child.stdin.on('error', () => {
      // EPIPE is expected when a provider exits before consuming all input.
    })

    const timer = setTimeout(() => fail('timeout'), request.timeoutMs)
    timer.unref()

    child.once('error', () => {
      fail('spawn')
    })

    child.once('exit', (exitCode, signal) => {
      // A provider must not leave background descendants running after review.
      void cleanup()
      // A helper that escaped that terminate still holds the pipes it
      // inherited, which is what `close` waits for. Settle on the provider's
      // own exit status after a bounded grace rather than discarding a review
      // it already produced once the deadline elapses.
      escapeTimer = setTimeout(() => {
        if (settled || failure) return
        succeed(exitCode, signal)
      }, LOCAL_COMMAND_ESCAPED_OUTPUT_GRACE_MS)
      escapeTimer.unref()
    })

    child.once('close', (exitCode, signal) => succeed(exitCode, signal))

    child.stdin.end(request.input ?? '')
  })
}
