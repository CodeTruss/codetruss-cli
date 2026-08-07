import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPairSync } from 'node:crypto'
import { afterEach, describe, expect, it } from 'vitest'
import { loadSigningKey, requireTrustedSigningKey } from '../src/signing.js'
import {
  APPROVED_RECEIPT_DIR,
  PRODUCTION_SYNC_ORIGIN,
  detectVerifyCommands,
  initialize,
  loadConfig,
  receiptDir,
  resolveSyncOrigin,
} from '../src/config.js'

const originalKey = process.env.CODETRUSS_SIGNING_KEY
const originalDevSyncOrigin = process.env.CODETRUSS_DEV_SYNC_ORIGIN
afterEach(() => {
  if (originalKey === undefined) delete process.env.CODETRUSS_SIGNING_KEY
  else process.env.CODETRUSS_SIGNING_KEY = originalKey
  if (originalDevSyncOrigin === undefined) delete process.env.CODETRUSS_DEV_SYNC_ORIGIN
  else process.env.CODETRUSS_DEV_SYNC_ORIGIN = originalDevSyncOrigin
})

describe('initialization', () => {
  it('writes only the explicit repository scope globs supplied at init time', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-init-policy-'))
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')

    await initialize(root, false, {
      allow: [' src/** ', 'tests/**'],
      deny: ['infra/production/**', '.env*'],
    })

    await expect(loadConfig(root)).resolves.toMatchObject({
      allow: ['src/**', 'tests/**'],
      deny: ['infra/production/**', '.env*'],
    })
    const configText = await readFile(join(root, '.codetruss.yml'), 'utf8')
    expect(configText).not.toContain('"**"')
  })

  it('rejects blank init globs before writing repository state', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-init-policy-invalid-'))
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')

    await expect(initialize(root, false, { allow: ['   '] })).rejects.toThrow(
      'init allow globs must be non-empty strings',
    )
    await expect(readFile(join(root, '.codetruss.yml'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('does not invent failing package scripts from a lockfile alone', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-init-'))
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    await writeFile(join(root, 'package.json'), `${JSON.stringify({ scripts: { dev: 'node app.js' } })}\n`)
    await writeFile(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n')
    await initialize(root)
    const config = await loadConfig(root)
    expect(config.verify).toEqual([])
    expect(config.signing.publicKey).toContain('BEGIN PUBLIC KEY')
    const configText = await readFile(join(root, '.codetruss.yml'), 'utf8')
    expect(configText).not.toContain('pnpm lint')
    expect(configText).not.toContain('sync:')
  })

  it('collects lint and test for every Node package manager, not just pnpm', async () => {
    // npm and yarn repositories were losing their lint script for no reason
    // other than which lockfile they happen to commit.
    const scripts = { scripts: { lint: 'eslint .', test: 'vitest run', dev: 'next dev' } }
    const withLockfile = async (name: string) => {
      const root = await mkdtemp(join(tmpdir(), 'codetruss-detect-verify-'))
      await writeFile(join(root, 'package.json'), `${JSON.stringify(scripts)}\n`)
      await writeFile(join(root, name), '\n')
      return detectVerifyCommands(root)
    }

    expect((await withLockfile('pnpm-lock.yaml')).candidates).toEqual(['pnpm lint', 'pnpm test'])
    // `npm lint` is not a command — only lifecycle names run without `run`.
    expect((await withLockfile('package-lock.json')).candidates).toEqual(['npm run lint', 'npm run test'])
    expect((await withLockfile('yarn.lock')).candidates).toEqual(['yarn lint', 'yarn test'])
  })

  it('names the missing lockfile as the reason detection found nothing', async () => {
    // "No verification commands were detected" reads as "this repository has no
    // tests" even when package.json defines them and only the lockfile is absent.
    const root = await mkdtemp(join(tmpdir(), 'codetruss-detect-no-lockfile-'))
    await writeFile(
      join(root, 'package.json'),
      `${JSON.stringify({ scripts: { lint: 'eslint .', test: 'vitest run' } })}\n`,
    )

    await expect(detectVerifyCommands(root)).resolves.toEqual({
      commands: [],
      candidates: ['lint', 'test'],
      blocker: 'missing-lockfile',
    })
  })

  it('claims no candidates when the repository genuinely defines none', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-detect-empty-'))
    await writeFile(join(root, 'package.json'), `${JSON.stringify({ scripts: { dev: 'next dev' } })}\n`)

    await expect(detectVerifyCommands(root)).resolves.toEqual({ commands: [], candidates: [] })
  })

  it('never accepts a repository-selected bearer-token destination', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-config-sync-'))
    await writeFile(join(root, '.codetruss.yml'), 'version: 1\nsync:\n  url: https://collector.invalid\n')
    await expect(loadConfig(root)).rejects.toThrow('cannot configure a sync destination')

    // Existing production-only configs remain readable, but the returned value
    // is still the application-owned invariant rather than repository input.
    await writeFile(join(root, '.codetruss.yml'), `version: 1\nsync:\n  url: ${PRODUCTION_SYNC_ORIGIN}\n`)
    await expect(loadConfig(root)).resolves.toMatchObject({ sync: { url: PRODUCTION_SYNC_ORIGIN } })
  })

  it('hard-binds production sync and permits only an explicit loopback dev origin', () => {
    delete process.env.CODETRUSS_DEV_SYNC_ORIGIN
    expect(resolveSyncOrigin(undefined)).toBe(PRODUCTION_SYNC_ORIGIN)
    expect(resolveSyncOrigin('http://localhost:3000')).toBe('http://localhost:3000')
    expect(resolveSyncOrigin('https://127.0.0.1:4443')).toBe('https://127.0.0.1:4443')
    expect(() => resolveSyncOrigin('https://collector.invalid')).toThrow('loopback origin')
    expect(() => resolveSyncOrigin('http://localhost:3000/steal')).toThrow('without credentials')
    expect(() => resolveSyncOrigin('http://token@localhost:3000')).toThrow('without credentials')
  })

  it('keeps legacy LLM config readable for deterministic commands', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-config-llm-'))
    await writeFile(join(root, '.codetruss.yml'), 'version: 1\nllm:\n  model: sonnet\n')
    await expect(loadConfig(root)).resolves.toMatchObject({ llm: { model: 'sonnet' } })

    await writeFile(join(root, '.codetruss.yml'), 'version: 1\nllm:\n  provider: codex\n')
    await expect(loadConfig(root)).resolves.toMatchObject({ llm: { provider: 'codex' } })

    await writeFile(join(root, '.codetruss.yml'), 'version: 1\nllm:\n  provider: claude\n  model: sonnet\n  maxDiffBytes: 200000\n')
    await expect(loadConfig(root)).resolves.toMatchObject({
      llm: { provider: 'claude', model: 'sonnet', maxDiffBytes: 200_000 },
    })
  })

  it('confines repository-configured receipt storage to the approved local tree', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-config-receipts-'))
    const config = await loadConfig(root)
    expect(receiptDir(root, config)).toBe(join(root, APPROVED_RECEIPT_DIR))

    config.receipts.dir = `${APPROVED_RECEIPT_DIR}/team-a`
    expect(receiptDir(root, config)).toBe(join(root, APPROVED_RECEIPT_DIR, 'team-a'))

    for (const unsafe of ['../receipts', '.codetruss/other', `${APPROVED_RECEIPT_DIR}-backup`, join(root, 'outside')]) {
      config.receipts.dir = unsafe
      expect(() => receiptDir(root, config)).toThrow(`must stay under ${APPROVED_RECEIPT_DIR}`)
    }

    if (process.platform !== 'win32') {
      const symlinkRoot = await mkdtemp(join(tmpdir(), 'codetruss-config-receipt-link-'))
      const outside = join(symlinkRoot, 'outside')
      await mkdir(outside)
      await symlink(outside, join(symlinkRoot, '.codetruss'), 'dir')
      config.receipts.dir = APPROVED_RECEIPT_DIR
      expect(() => receiptDir(symlinkRoot, config)).toThrow('must not traverse symbolic links')
    }
  })
})

/**
 * A committed .codetruss.yml pins the signing key. With a single-key pin, every
 * teammate who clones gets exit 3 and no receipt, and the old error told them to
 * "set CODETRUSS_SIGNING_KEY to the trusted private key" — i.e. to obtain a
 * colleague's private key, which destroys the per-signer attribution the receipt
 * exists to provide. Bad advice from a security product.
 */
describe('multi-developer signing pins', () => {
  it('accepts a publicKeys list and keeps publicKey as the first entry', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-multikey-'))
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const a = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString()
    const b = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString()
    await writeFile(
      join(root, '.codetruss.yml'),
      `allow: ["src/**"]\nsigning:\n  publicKeys:\n    - |\n${a.trimEnd().split('\n').map((l) => `      ${l}`).join('\n')}\n    - |\n${b.trimEnd().split('\n').map((l) => `      ${l}`).join('\n')}\n`,
      'utf8',
    )
    const config = await loadConfig(root)
    expect(config.signing.publicKeys).toHaveLength(2)
    expect(config.signing.publicKey).toBe(config.signing.publicKeys[0])
  })

  it('still accepts a single legacy publicKey', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-singlekey-'))
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    await initialize(root)
    const config = await loadConfig(root)
    expect(config.signing.publicKeys).toHaveLength(1)
    expect(config.signing.publicKeys[0]).toContain('BEGIN PUBLIC KEY')
    expect(config.signing.publicKey).toBe(config.signing.publicKeys[0])
  })

  it('trusts any pinned key and never tells the reader to obtain a private key', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-trust-'))
    process.env.CODETRUSS_SIGNING_KEY = join(root, 'signing.pem')
    const mine = await loadSigningKey(true)
    const teammate = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString()

    // My key is in the pinned set alongside a teammate's: allowed.
    await expect(requireTrustedSigningKey([teammate, mine.publicKey])).resolves.toMatchObject({
      fingerprint: mine.fingerprint,
    })

    // My key is absent: rejected, but the guidance must not be "get their key".
    await expect(requireTrustedSigningKey([teammate])).rejects.toThrow(/verify-policy trust-key/)
    await expect(requireTrustedSigningKey([teammate])).rejects.not.toThrow(/private key/)
  })
})
