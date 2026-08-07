import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  revokeVerifyCommands,
  trustVerifyCommands,
  verifyCommandTrustHash,
  verifyCommandTrustStatus,
  verifyTrustFilePath,
} from '../src/verify-trust.js'

/** A real environment with XDG_CONFIG_HOME set, or explicitly unset. */
function env(configHome?: string): NodeJS.ProcessEnv {
  return { ...process.env, XDG_CONFIG_HOME: configHome }
}

/** Node's homedir() reads $HOME on POSIX and %USERPROFILE% on Windows. */
async function withHome(home: string, body: () => Promise<void>): Promise<void> {
  const prior = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE }
  process.env.HOME = home
  process.env.USERPROFILE = home
  try {
    await body()
  } finally {
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
  }
}

describe('user-local verification command trust', () => {
  it('binds trust to the canonical repository and exact ordered commands without storing either', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-verify-trust-'))
    const root = join(parent, 'repo')
    const otherRoot = join(parent, 'other-repo')
    const trustFile = join(parent, 'user-config', 'verify-command-trust.json')
    const commands = ['pnpm lint', 'pnpm test -- --runInBand']

    const initial = await verifyCommandTrustStatus(root, commands, trustFile)
    expect(initial).toMatchObject({ trusted: false, trustFile })
    expect(initial.hash).toMatch(/^[0-9a-f]{64}$/)

    const trusted = await trustVerifyCommands(root, commands, trustFile, new Date('2026-07-14T12:00:00.000Z'))
    expect(trusted).toEqual({ hash: initial.hash, trusted: true, trustFile })
    await expect(verifyCommandTrustStatus(root, commands, trustFile)).resolves.toMatchObject({ trusted: true })
    await expect(verifyCommandTrustStatus(root, [...commands].reverse(), trustFile)).resolves.toMatchObject({ trusted: false })
    expect(await verifyCommandTrustHash(otherRoot, commands)).not.toBe(initial.hash)

    const stored = await readFile(trustFile, 'utf8')
    expect(JSON.parse(stored)).toEqual({
      version: 1,
      trusted: { [initial.hash]: { trustedAt: '2026-07-14T12:00:00.000Z' } },
    })
    expect(stored).not.toContain(root)
    expect(stored).not.toContain('pnpm lint')

    await expect(revokeVerifyCommands(root, commands, trustFile)).resolves.toMatchObject({ trusted: false })
    await expect(verifyCommandTrustStatus(root, commands, trustFile)).resolves.toMatchObject({ trusted: false })
  })

  it('honors XDG_CONFIG_HOME without orphaning an existing trust store', async () => {
    // auth-storage.ts already honors XDG_CONFIG_HOME; this file honored only
    // homedir(), so one user's CodeTruss state was split across two directories.
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-xdg-'))
    const home = join(parent, 'home')
    const configHome = join(parent, 'xdg')
    await mkdir(home, { recursive: true })
    const legacy = join(home, '.config', 'codetruss', 'verify-command-trust.json')
    const preferred = join(configHome, 'codetruss', 'verify-command-trust.json')

    await withHome(home, async () => {
      expect(homedir()).toBe(home)
      expect(verifyTrustFilePath(env())).toBe(legacy)
      expect(verifyTrustFilePath(env('   '))).toBe(legacy)
      expect(verifyTrustFilePath(env(configHome))).toBe(preferred)
      expect(() => verifyTrustFilePath(env('relative/config')))
        .toThrow('XDG_CONFIG_HOME must be an absolute user config path')
    })
  })

  it('keeps reading an approval already stored at the legacy path', async () => {
    // Migration: setting XDG_CONFIG_HOME must never silently revoke commands
    // the user already inspected and trusted.
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-xdg-migration-'))
    const home = join(parent, 'home')
    const configHome = join(parent, 'xdg')
    await mkdir(home, { recursive: true })
    const legacy = join(home, '.config', 'codetruss', 'verify-command-trust.json')
    const preferred = join(configHome, 'codetruss', 'verify-command-trust.json')

    await withHome(home, async () => {
      // An approval made before XDG_CONFIG_HOME was set keeps being honored.
      await trustVerifyCommands(home, ['pnpm test'], legacy)
      expect(verifyTrustFilePath(env(configHome))).toBe(legacy)
      await expect(
        verifyCommandTrustStatus(home, ['pnpm test'], verifyTrustFilePath(env(configHome))),
      ).resolves.toMatchObject({ trusted: true })

      // Once a store exists at the XDG path it wins outright.
      await mkdir(join(configHome, 'codetruss'), { recursive: true })
      await writeFile(preferred, '{"version":1,"trusted":{}}\n')
      expect(verifyTrustFilePath(env(configHome))).toBe(preferred)
    })
  })

  it('fails closed on a corrupt user trust store', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'codetruss-verify-trust-corrupt-'))
    const trustFile = join(parent, 'verify-command-trust.json')
    await writeFile(trustFile, '{"version":1,"trusted":{"not-a-hash":{}}}\n')
    await expect(verifyCommandTrustStatus(parent, ['npm test'], trustFile)).rejects.toThrow(
      'invalid; refusing to trust repository commands',
    )
  })
})
