import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

// Windows, simulated on any host: `relative` is the ONLY platform-shaped call in
// the repository walk, so swapping it for its win32 counterpart reproduces the
// separator a Windows run would actually produce. Everything else — `join`, the
// filesystem — stays real, which is what makes the assertion meaningful: an
// un-normalized `src\deep\users.ts` cannot even be stat'd back on this host, so
// the file drops out of the index entirely.
vi.mock('node:path', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:path')>()
  return { ...actual, default: actual, relative: actual.win32.relative }
})

const { indexRepository } = await import('../src/indexer.js')

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('repository index path separators', () => {
  it('emits POSIX separators for nested files even when the platform yields backslashes', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-index-separators-'))
    roots.push(root)
    await mkdir(join(root, 'src', 'deep'), { recursive: true })
    await writeFile(join(root, 'src', 'deep', 'users.ts'), 'export const users = []\n')
    await writeFile(join(root, 'root.ts'), 'export const root = 1\n')

    const index = await indexRepository(root)
    const paths = index.files.map((file) => file.path).sort()

    expect(paths).toEqual(['root.ts', 'src/deep/users.ts'])
    for (const path of paths) expect(path).not.toContain('\\')
  })

  it('still reads content for nested files after normalization', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-index-separators-'))
    roots.push(root)
    await mkdir(join(root, 'src', 'deep'), { recursive: true })
    await writeFile(join(root, 'src', 'deep', 'users.ts'), 'export const users = []\n')

    const index = await indexRepository(root)

    expect(index.files).toEqual([
      expect.objectContaining({ path: 'src/deep/users.ts', content: 'export const users = []\n' }),
    ])
  })
})
