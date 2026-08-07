import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { indexRepository } from '../src/indexer.js'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('local binary-aware indexing profile', () => {
  it.each(['release.tgz', 'font.woff2', 'module.wasm'])(
    'treats %s as an asset without changing the hosted historical default',
    async (name) => {
      const root = await mkdtemp(join(tmpdir(), 'codetruss-local-binary-index-'))
      roots.push(root)
      await writeFile(join(root, name), Buffer.from([0x00, 0x01, 0x02, 0x03]))

      const index = await indexRepository(root)

      expect(index.files).toEqual([
        expect.objectContaining({ path: name, kind: 'asset', content: null }),
      ])
      expect(index.coverage).toMatchObject({
        textCandidates: 0,
        contentLoaded: 0,
        oversizedTextFiles: 0,
        unreadableTextFiles: 0,
        binaryTextFiles: 0,
      })
    },
  )

  // On a Windows host this runs unsimulated and is the real guard; elsewhere it
  // pins the contract that indexed paths are the same bytes on every platform.
  // See indexer-path-separators.test.ts for the host-independent version.
  it('indexes nested files under POSIX separators on this platform', async () => {
    const root = await mkdtemp(join(tmpdir(), 'codetruss-local-index-separators-'))
    roots.push(root)
    await mkdir(join(root, 'src', 'deep'), { recursive: true })
    await writeFile(join(root, 'src', 'deep', 'users.ts'), 'export const users = []\n')

    const index = await indexRepository(root)

    expect(index.files.map((file) => file.path)).toEqual(['src/deep/users.ts'])
  })
})
