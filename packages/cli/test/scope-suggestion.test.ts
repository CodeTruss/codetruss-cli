import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { suggestedAllowGlobs } from '../src/setup.js'

/**
 * The 2026-08-14 field failure: a monorepo whose work lives in a nested app
 * named after the product (selevita-app/) got a suggested scope of server/**
 * and docs/** only, so every legitimate edit flagged as drift. Suggestion must
 * see what is actually in the repository, not just probe a fixed name list.
 */

async function repo(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'codetruss-scope-'))
}

describe('suggested allow globs', () => {
  it('finds a nested app the conventional name list misses', async () => {
    const root = await repo()
    await mkdir(join(root, 'server'))
    await mkdir(join(root, 'docs'))
    await mkdir(join(root, 'selevita-app', 'src'), { recursive: true })
    await writeFile(join(root, 'selevita-app', 'package.json'), '{"name":"selevita-app"}')

    const globs = await suggestedAllowGlobs(root)
    expect(globs).toContain('server/**')
    expect(globs).toContain('docs/**')
    expect(globs).toContain('selevita-app/**')
  })

  it('reads workspace manifests as declared roots', async () => {
    const root = await repo()
    await writeFile(join(root, 'package.json'), JSON.stringify({ name: 'r', workspaces: ['modules/*'] }))
    await mkdir(join(root, 'modules'))
    const globs = await suggestedAllowGlobs(root)
    expect(globs).toContain('modules/**')

    const pnpmRoot = await repo()
    await writeFile(join(pnpmRoot, 'pnpm-workspace.yaml'), 'packages:\n  - services/*\n')
    await mkdir(join(pnpmRoot, 'services'))
    expect(await suggestedAllowGlobs(pnpmRoot)).toContain('services/**')
  })

  it('never suggests junk, hidden, excluded, or symlinked directories', async () => {
    const root = await repo()
    await mkdir(join(root, 'src'))
    // A directory with no manifest and no src child is not a project root.
    await mkdir(join(root, 'notes'))
    await mkdir(join(root, '.cache'))
    // Excluded even though it carries a manifest.
    await mkdir(join(root, 'dist'))
    await writeFile(join(root, 'dist', 'package.json'), '{}')
    // A symlinked directory that would otherwise qualify.
    await mkdir(join(root, 'real-app'))
    await writeFile(join(root, 'real-app', 'package.json'), '{}')
    await symlink(join(root, 'real-app'), join(root, 'linked-app'))

    const globs = await suggestedAllowGlobs(root)
    expect(globs).toContain('src/**')
    expect(globs).toContain('real-app/**')
    expect(globs).not.toContain('notes/**')
    expect(globs).not.toContain('.cache/**')
    expect(globs).not.toContain('dist/**')
    expect(globs).not.toContain('linked-app/**')
  })

  it('suggests each root exactly once when manifests and the scan agree', async () => {
    const root = await repo()
    await writeFile(join(root, 'package.json'), JSON.stringify({ name: 'r', workspaces: ['packages/*'] }))
    await mkdir(join(root, 'packages'))
    const globs = await suggestedAllowGlobs(root)
    expect(globs.filter((glob) => glob === 'packages/**')).toHaveLength(1)
  })
})
