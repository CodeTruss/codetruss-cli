import { spawnSync } from 'node:child_process'
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_CONFIG } from '../src/config.js'
import { handleAgentHook, type HookReviewRequest } from '../src/hook-runtime.js'
import { writeInternalHookResult } from '../src/hook-result.js'
import type { CliConfig } from '../src/types.js'

const cleanup: string[] = []
const attemptId = 'b'.repeat(64)

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function git(root: string, ...args: string[]): string {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(' ')} failed`)
  return result.stdout.trim()
}

async function repo(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codetruss-fix-hook-'))
  cleanup.push(root)
  git(root, 'init', '--quiet')
  git(root, 'config', 'user.name', 'Hook Test')
  git(root, 'config', 'user.email', 'hook@example.com')
  await writeFile(join(root, 'README.md'), 'baseline\n')
  git(root, 'add', 'README.md')
  git(root, 'commit', '--quiet', '-m', 'baseline')
  await writeFile(join(root, '.codetruss.yml'), 'version: 1\nallow:\n  - src/**\ndeny:\n  - vendor/**\nverify: []\n')
  return root
}

function config(allow = ['src/**']): CliConfig {
  return { ...structuredClone(DEFAULT_CONFIG), allow, deny: ['vendor/**'] }
}

const SUGGESTION = 'Suggested fix (NOT applied — review before using) for HIGH "Possible AWS access key committed in config.ts" at src/config.ts:12: '
  + 'Read the credential from `AWS_KEY` at runtime and document it in .env.example. Rotate this credential first.'

/** More reasons than the Stop summary displays, so truncation is exercised. */
const REASONS = Array.from({ length: 8 }, (_, position) => `verdict reason ${position + 1}`)

/**
 * Drive one real prompt/Stop turn and return whatever the agent is shown.
 * The suggestion has to survive the same validator, the same reason cap, and
 * the same message assembly a live hook uses — asserting on the builder alone
 * would prove nothing about what the agent actually reads.
 */
async function stopOutput(
  writeResult: (request: HookReviewRequest, receiptPath: string) => Promise<void>,
): Promise<unknown> {
  const root = await repo()
  const receiptPath = join(root, '.codetruss', 'receipts', 'hook.md')
  await mkdir(join(root, '.codetruss', 'receipts'), { recursive: true })
  await writeFile(receiptPath, '# receipt\n')
  const runReview = vi.fn(async (request: HookReviewRequest) => {
    await writeResult(request, receiptPath)
    return { status: 1 as const, stdout: '', stderr: '' }
  })
  const dependencies = { runReview, now: () => new Date() }
  await mkdir(join(root, 'src'), { recursive: true })
  await writeFile(join(root, 'src', 'config.ts'), 'export const value = "before"\n')
  const prompt = { session_id: 'session-fix', turn_id: 'turn-1', hook_event_name: 'UserPromptSubmit', prompt: 'Wire up billing', cwd: root }
  await handleAgentHook(root, 'codex', prompt, config(), dependencies)
  await writeFile(join(root, 'src', 'config.ts'), 'export const value = "after"\n')
  return handleAgentHook(root, 'codex', { ...prompt, hook_event_name: 'Stop', background_tasks: [] }, config(), dependencies)
}

describe('the Stop hook hands the agent one suggestion', () => {
  it('shows the suggestion even when the verdict reasons fill the display cap', async () => {
    const output = await stopOutput(async (request, receiptPath) => {
      await writeFile(request.resultPath, `${JSON.stringify({
        version: 1,
        attemptId: request.attemptId,
        verdict: 'REVIEW_REQUIRED',
        receiptPath,
        reasons: REASONS,
        suggestion: SUGGESTION,
      })}\n`, { mode: 0o600, flag: 'wx' })
    })

    const message = JSON.stringify(output)
    expect(message).toContain('CodeTruss REVIEW_REQUIRED')
    expect(message).toContain('verdict reason 1')
    // The reason list is capped at five; the suggestion is not part of it.
    expect(message).not.toContain('verdict reason 6')
    expect(JSON.parse(message).systemMessage).toContain(SUGGESTION)
    expect(JSON.parse(message).systemMessage.indexOf(SUGGESTION))
      .toBeGreaterThan(JSON.parse(message).systemMessage.indexOf('verdict reason 5'))
  })

  it('still accepts a result written by a CLI that has no suggestions', async () => {
    const output = await stopOutput(async (request, receiptPath) => {
      await writeFile(request.resultPath, `${JSON.stringify({
        version: 1,
        attemptId: request.attemptId,
        verdict: 'REVIEW_REQUIRED',
        receiptPath,
        reasons: ['outside allowed scope'],
      })}\n`, { mode: 0o600, flag: 'wx' })
    })
    expect(JSON.stringify(output)).toContain('outside allowed scope')
    expect(JSON.stringify(output)).not.toContain('Suggested fix')
  })

  it('rejects a result whose suggestion is not a bounded string', async () => {
    const output = await stopOutput(async (request, receiptPath) => {
      await writeFile(request.resultPath, `${JSON.stringify({
        version: 1,
        attemptId: request.attemptId,
        verdict: 'REVIEW_REQUIRED',
        receiptPath,
        reasons: [],
        suggestion: { description: 'structured payloads are not accepted here' },
      })}\n`, { mode: 0o600, flag: 'wx' })
    })
    expect(JSON.stringify(output)).toContain('invalid schema or attempt binding')
  })
})

describe('the internal hook result carries the suggestion separately from reasons', () => {
  async function resultFixture(): Promise<{ contextPath: string; receiptPath: string; resultPath: string }> {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-fix-result-'))
    cleanup.push(root)
    const attempts = join(root, 'turn', 'attempts')
    await mkdir(attempts, { recursive: true, mode: 0o700 })
    const contextPath = join(root, 'turn', 'turn-context.json')
    const receiptPath = join(root, 'receipt.md')
    await writeFile(contextPath, '{}\n', { mode: 0o600 })
    await writeFile(receiptPath, '# receipt\n', { mode: 0o600 })
    return { contextPath, receiptPath, resultPath: join(attempts, 'result.json') }
  }

  it('writes the suggestion as its own bounded field', async () => {
    const files = await resultFixture()
    await writeInternalHookResult(
      { path: files.resultPath, attemptId },
      files.contextPath,
      { verdict: 'REVIEW_REQUIRED', receiptPath: files.receiptPath, reasons: ['outside allowed scope'], suggestion: SUGGESTION },
    )
    expect(JSON.parse(await readFile(files.resultPath, 'utf8'))).toEqual({
      version: 1,
      attemptId,
      verdict: 'REVIEW_REQUIRED',
      receiptPath: files.receiptPath,
      reasons: ['outside allowed scope'],
      suggestion: SUGGESTION,
    })
    if (process.platform !== 'win32') expect((await lstat(files.resultPath)).mode & 0o777).toBe(0o600)
  })

  it('omits the field entirely when nothing carried a fix', async () => {
    const files = await resultFixture()
    await writeInternalHookResult(
      { path: files.resultPath, attemptId },
      files.contextPath,
      { verdict: 'PASS', receiptPath: files.receiptPath, reasons: [] },
    )
    expect(Object.keys(JSON.parse(await readFile(files.resultPath, 'utf8')))).toEqual([
      'version', 'attemptId', 'verdict', 'receiptPath', 'reasons',
    ])
  })
})
