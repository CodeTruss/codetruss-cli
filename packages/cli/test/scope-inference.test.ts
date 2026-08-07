import { describe, expect, it } from 'vitest'
import { applyInferredScope, inferTurnScope, type ScopeCandidate } from '../src/scope-inference.js'
import { computeVerdict } from '../src/analysis.js'
import { classifyPath, isDependencyFile, sensitiveCategory } from '../src/policy.js'
import type { ChangedFile } from '../src/types.js'

/**
 * Scope drift is the detection nobody else ships, and on a stranger's first
 * session it fires on the first reasonable edit outside whatever directories
 * `setup` found on disk. These cases pin the line between "in scope on weaker
 * evidence, and said so" and real drift.
 */

/** Classify exactly as a review does, so a case can never assume its own answer. */
function turn(paths: Array<string | [string, string]>, allow: string[], deny: string[] = []): ChangedFile[] {
  return paths.map((entry) => {
    const [path, oldPath] = Array.isArray(entry) ? entry : [entry, undefined]
    return {
      path,
      ...(oldPath ? { oldPath } : {}),
      change: oldPath ? 'renamed' : 'modified',
      classification: classifyPath(path, oldPath, allow, deny),
      ...(sensitiveCategory(path) ? { sensitive: sensitiveCategory(path)! } : {}),
      dependency: isDependencyFile(path),
      additions: 1,
      deletions: 0,
    } satisfies ChangedFile
  })
}

function resolve(task: string, files: ChangedFile[], allow: string[], deny: string[] = []) {
  return applyInferredScope(files, inferTurnScope({ task, files, allow, deny }))
}

function scope(files: ScopeCandidate[]): Record<string, string> {
  return Object.fromEntries(files.map((file) => [file.path, file.classification]))
}

describe('turn-scoped scope inference', () => {
  it('reads a cohesive working set as in scope and an unrelated subsystem as drift', () => {
    const allow = ['lib/**']
    const files = turn([
      'src/auth/password-reset.ts',
      'src/auth/tokens.ts',
      'src/billing/webhooks.ts',
    ], allow)

    const { files: classified, roots } = resolve('Add password reset', files, allow)

    expect(scope(classified)).toEqual({
      'src/auth/password-reset.ts': 'inferred',
      'src/auth/tokens.ts': 'inferred',
      'src/billing/webhooks.ts': 'unexpected',
    })
    expect(roots).toEqual([{
      root: 'src/auth',
      basis: 'working-set',
      evidence: ['src/auth/password-reset.ts', 'src/auth/tokens.ts'],
    }])
  })

  it('leaves a lone file in an unnamed subsystem outside scope', () => {
    const allow = ['lib/**']
    const files = turn(['src/billing/webhooks.ts'], allow)

    const { files: classified, roots } = resolve('Add password reset', files, allow)

    expect(scope(classified)).toEqual({ 'src/billing/webhooks.ts': 'unexpected' })
    expect(roots).toEqual([])
  })

  it('takes a single file in scope when the task names its path', () => {
    const allow = ['lib/**']
    const files = turn(['src/auth/password-reset.ts'], allow)

    const { files: classified, roots } = resolve('Add password reset under src/auth', files, allow)

    expect(scope(classified)).toEqual({ 'src/auth/password-reset.ts': 'inferred' })
    expect(roots).toEqual([{ root: 'src/auth', basis: 'task-reference', evidence: ['src/auth'] }])
  })

  it('takes a single file in scope when the task names its directory by feature name', () => {
    const allow = ['lib/**']
    const files = turn(['src/password-reset/token.ts'], allow)

    const { files: classified, roots } = resolve('Add password reset', files, allow)

    expect(scope(classified)).toEqual({ 'src/password-reset/token.ts': 'inferred' })
    expect(roots).toEqual([{ root: 'src/password-reset', basis: 'task-reference', evidence: ['password reset'] }])
  })

  it('never treats a generic directory name as the subject of the task', () => {
    const allow = ['lib/**']
    const files = turn(['scripts/seed.ts'], allow)

    const { roots } = resolve('Add a script that seeds the database', files, allow)

    expect(roots).toEqual([])
  })

  it('never lets inference reopen a denied path', () => {
    const allow = ['lib/**']
    const deny = ['src/auth/secrets.ts']
    const files = turn(['src/auth/reset.ts', 'src/auth/tokens.ts', 'src/auth/secrets.ts'], allow, deny)

    const { files: classified, roots } = resolve('Add password reset', files, allow, deny)

    expect(scope(classified)).toEqual({
      'src/auth/reset.ts': 'inferred',
      'src/auth/tokens.ts': 'inferred',
      'src/auth/secrets.ts': 'denied',
    })
    expect(roots.map((root) => root.root)).toEqual(['src/auth'])
  })

  it('never infers scope for a secrets, config, or dependency surface inside an inferred root', () => {
    const files = turn([
      'src/auth/reset.ts',
      'src/auth/.env.local',
      'src/auth/package.json',
      'prisma/migrations/001_add_reset.sql',
    ], [])

    const { files: classified } = resolve('Add password reset', files, [])

    expect(scope(classified)).toEqual({
      'src/auth/reset.ts': 'inferred',
      'src/auth/.env.local': 'unexpected',
      'src/auth/package.json': 'unexpected',
      'prisma/migrations/001_add_reset.sql': 'unexpected',
    })
  })

  it('refuses to climb above an allow root the repository deliberately narrowed', () => {
    const allow = ['src/auth/**']
    const files = turn(['src/billing/invoice.ts', 'src/billing/webhooks.ts'], allow)

    // `src` would swallow the sibling the repository chose not to approve.
    // A named sibling working set may still be inferred; its parent may not.
    const { roots } = resolve('Rework invoices', files, allow)
    expect(roots.map((root) => root.root)).toEqual(['src/billing'])

    const climbing = resolve('Rework invoices', turn(['src/a.ts', 'src/b.ts'], allow), allow)
    expect(climbing.roots).toEqual([])
    expect(scope(climbing.files)).toEqual({ 'src/a.ts': 'unexpected', 'src/b.ts': 'unexpected' })
  })

  it('makes the turn its own scope when no allow root was ever approved, but never the repository root', () => {
    const files = turn(['server/handlers/reset.ts', 'README.md'], [])

    const { files: classified, roots } = resolve('Add password reset', files, [])

    expect(scope(classified)).toEqual({
      'server/handlers/reset.ts': 'inferred',
      'README.md': 'unexpected',
    })
    expect(roots.map((root) => root.root)).toEqual(['server/handlers'])
  })

  // The 0.2.36 teardown ran the unconfigured first-run demo — no .codetruss.yml,
  // no --allow — and the file the task never mentioned came back `inferred`, so
  // the one detection nobody else ships reported nothing on the one path every
  // stranger walks. Each file had seated its own directory as a working set.
  it('does not let a lone file vouch for its own directory while the turn infers elsewhere', () => {
    const files = turn(['src/lib/billing.ts', 'src/routes/tasks.ts'], [])

    const { files: classified, roots } = resolve('Add free-text search to the task list endpoint', files, [])

    // Two lone files in two directories, no configured scope, and a task naming
    // no path: nothing here says which directory the turn was about. Blessing
    // both is the circular answer, and picking one would be a guess.
    expect(scope(classified)).toEqual({
      'src/lib/billing.ts': 'unexpected',
      'src/routes/tasks.ts': 'unexpected',
    })
    expect(roots).toEqual([])
  })

  it('still seats a single file when that root is the whole of what the turn inferred', () => {
    const files = turn(['src/routes/tasks.ts'], [])

    const { files: classified, roots } = resolve('Add free-text search to the task list endpoint', files, [])

    expect(scope(classified)).toEqual({ 'src/routes/tasks.ts': 'inferred' })
    expect(roots).toEqual([{ root: 'src/routes', basis: 'working-set', evidence: ['src/routes/tasks.ts'] }])
  })

  it('refuses to widen a scope the task already declared with a lone file elsewhere', () => {
    const files = turn(['src/auth/reset.ts', 'src/mailer/send.ts'], [])

    // The task named src/auth and the turn changed a file under it, so the task
    // has said what this turn is about. The stray mailer file is the drift.
    const { files: classified, roots } = resolve('Add password reset under src/auth', files, [])

    expect(scope(classified)).toEqual({
      'src/auth/reset.ts': 'inferred',
      'src/mailer/send.ts': 'unexpected',
    })
    expect(roots).toEqual([{ root: 'src/auth', basis: 'task-reference', evidence: ['src/auth'] }])
  })

  it('still admits a genuine second cluster beside a root the task named', () => {
    const files = turn([
      'src/auth/reset.ts',
      'src/mailer/send.ts',
      'src/mailer/templates.ts',
    ], [])

    // A new sibling subsystem the turn actually built out clears cohesion 2 on
    // its own evidence; only the lone file could not.
    const { files: classified, roots } = resolve('Add password reset under src/auth', files, [])

    expect(scope(classified)).toEqual({
      'src/auth/reset.ts': 'inferred',
      'src/mailer/send.ts': 'inferred',
      'src/mailer/templates.ts': 'inferred',
    })
    expect(roots.map((root) => root.root)).toEqual(['src/auth', 'src/mailer'])
  })

  it('admits a new sibling directory the task named by feature, however few files it has', () => {
    const files = turn(['src/auth/reset.ts', 'src/password-reset/token.ts'], [])

    // Creating a directory named for the feature is the task naming it: the
    // feature-name rule reaches it without any help from cohesion.
    const { files: classified } = resolve('Add password reset under src/auth', files, [])

    expect(scope(classified)).toEqual({
      'src/auth/reset.ts': 'inferred',
      'src/password-reset/token.ts': 'inferred',
    })
  })

  it('will not seat a rename destination on a single file once the task named a root', () => {
    const files = turn(['src/auth/reset.ts', ['src/mailer/send.ts', 'src/auth/send.ts']], [])

    // Moving a file out of the declared root and into a directory of its own is
    // exactly the drift a single-file working set used to launder.
    const { files: classified } = resolve('Add password reset under src/auth', files, [])

    expect(scope(classified)).toEqual({
      'src/auth/reset.ts': 'inferred',
      'src/mailer/send.ts': 'unexpected',
    })
  })

  it('admits a test file only when it mirrors a source file already in scope', () => {
    const allow = ['src/**']
    const files = turn(['src/auth/reset.ts', 'tests/auth/reset.test.ts', 'tests/billing/refund.test.ts'], allow)

    const { files: classified, roots } = resolve('Add password reset', files, allow)

    expect(scope(classified)).toEqual({
      'src/auth/reset.ts': 'allowed',
      'tests/auth/reset.test.ts': 'inferred',
      'tests/billing/refund.test.ts': 'unexpected',
    })
    expect(roots).toEqual([{
      root: 'tests/auth/reset.test.ts',
      basis: 'sibling-test',
      evidence: ['src/auth/reset.ts'],
    }])
  })

  it('holds a rename in scope only when its origin is in scope too, and reports no allowance that covered nothing', () => {
    const files = turn([['src/auth/reset.ts', 'infra/legacy-reset.ts']], [])

    const { files: classified, roots } = resolve('Add password reset', files, [])

    expect(scope(classified)).toEqual({ 'src/auth/reset.ts': 'unexpected' })
    expect(roots).toEqual([])
  })

  it('is a pure function of the task, the changed files, and the policy, so a receipt can be replayed', () => {
    const allow = ['lib/**']
    const files = turn(['src/auth/reset.ts', 'src/auth/tokens.ts'], allow)

    expect(inferTurnScope({ task: 'Add password reset', files, allow, deny: [] }))
      .toEqual(inferTurnScope({ task: 'Add password reset', files, allow, deny: [] }))
  })
})

describe('inferred scope on the verdict', () => {
  const verdictFor = (files: ChangedFile[]) => computeVerdict({
    agentExitCode: 0,
    verifications: [{ command: 'test', exitCode: 0, durationMs: 1, output: '', truncated: false }],
    files,
    startDirty: false,
    findings: [],
  })

  it('keeps an inferred path out of the drift reasons and never calls it approved scope', () => {
    const allow = ['lib/**']
    const { files } = resolve('Add password reset', turn(['src/auth/reset.ts', 'src/auth/tokens.ts'], allow), allow)

    const outcome = verdictFor(files)

    expect(outcome.verdict).toBe('PASS')
    expect(outcome.reasons.join('\n')).not.toContain('outside approved scope')
    expect(outcome.reasons).toContain(
      '0 changed file(s) are within approved scope; 2 more matched scope inferred from this turn and disclosed on the receipt',
    )
  })

  it('still requires review for the file inference refused to cover', () => {
    const allow = ['lib/**']
    const { files } = resolve(
      'Add password reset',
      turn(['src/auth/reset.ts', 'src/auth/tokens.ts', 'src/billing/webhooks.ts'], allow),
      allow,
    )

    const outcome = verdictFor(files)

    expect(outcome.verdict).toBe('REVIEW_REQUIRED')
    expect(outcome.reasons).toContain('1 file(s) changed outside approved scope: src/billing/webhooks.ts')
  })

  it('keeps the approved-scope sentence unchanged when nothing was inferred', () => {
    expect(verdictFor(turn(['src/a.ts'], ['src/**'])).reasons)
      .toContain('all 1 changed file(s) are within approved scope')
  })
})
