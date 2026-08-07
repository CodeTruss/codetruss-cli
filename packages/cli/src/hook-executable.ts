import { constants as fsConstants } from 'node:fs'
import { access, readFile, realpath } from 'node:fs/promises'
import { delimiter, dirname, join, parse as parsePath } from 'node:path'

/** The `codetruss` binary the installed hooks will resolve: repository-local first, then PATH. */
export async function executablePath(root: string): Promise<string | undefined> {
  const local = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'codetruss.cmd' : 'codetruss')
  if (await access(local, fsConstants.X_OK).then(() => true, () => false)) return local
  const extensions = process.platform === 'win32'
    ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';')
    : ['']
  for (const directory of (process.env.PATH ?? '').split(delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = join(directory, `codetruss${extension.toLowerCase()}`)
      if (await access(candidate, fsConstants.X_OK).then(() => true, () => false)) return candidate
    }
  }
  return undefined
}

/**
 * Version of the @codetruss/cli install that owns `executable`, read from its
 * package manifest. Never executes the binary: resolving a shadowing install
 * must not run whatever happens to be first on PATH.
 */
export async function installedCliVersion(executable: string): Promise<string | undefined> {
  let cursor: string
  try {
    cursor = dirname(await realpath(executable))
  } catch {
    return undefined
  }
  const { root } = parsePath(cursor)
  while (true) {
    try {
      const manifest = JSON.parse(await readFile(join(cursor, 'package.json'), 'utf8')) as {
        name?: unknown
        version?: unknown
      }
      if (manifest.name === '@codetruss/cli' && typeof manifest.version === 'string') return manifest.version
    } catch {
      // no manifest here, or unreadable — keep walking up
    }
    if (cursor === root) return undefined
    const parent = dirname(cursor)
    if (parent === cursor) return undefined
    cursor = parent
  }
}
