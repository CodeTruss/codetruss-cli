import { randomUUID } from 'node:crypto'
import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'

export interface PlannedWrite {
  path: string
  contents: Buffer
  defaultMode: number
  forceMode?: number
}

interface FileSnapshot {
  path: string
  exists: boolean
  contents?: Buffer
  mode?: number
}

export interface HookInstallPlan {
  writes: PlannedWrite[]
  installedPaths: string[]
}

export function plannedWrite(path: string, contents: string | Buffer, defaultMode: number, forceMode?: number): PlannedWrite {
  return {
    path: resolve(path),
    contents: Buffer.isBuffer(contents) ? Buffer.from(contents) : Buffer.from(contents, 'utf8'),
    defaultMode,
    ...(forceMode === undefined ? {} : { forceMode }),
  }
}

async function snapshotFile(path: string): Promise<FileSnapshot> {
  try {
    const metadata = await lstat(path)
    if (!metadata.isFile()) {
      throw new Error(`refusing to replace non-regular hook file ${path}`)
    }
    return {
      path,
      exists: true,
      contents: await readFile(path),
      mode: metadata.mode & 0o777,
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { path, exists: false }
    throw error
  }
}

async function snapshotStillMatches(snapshot: FileSnapshot): Promise<boolean> {
  try {
    const metadata = await lstat(snapshot.path)
    if (!snapshot.exists || !metadata.isFile()) return false
    const contents = await readFile(snapshot.path)
    return contents.equals(snapshot.contents!) && (metadata.mode & 0o777) === snapshot.mode
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return !snapshot.exists
    throw error
  }
}

async function writeTemporaryFile(write: PlannedWrite, mode: number): Promise<string> {
  await mkdir(dirname(write.path), { recursive: true })
  const temporary = join(dirname(write.path), `.${basename(write.path)}.codetruss-${process.pid}-${randomUUID()}.tmp`)
  try {
    await writeFile(temporary, write.contents, { flag: 'wx', mode })
    await chmod(temporary, mode)
    return temporary
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined)
    throw error
  }
}

export function mergePlannedWrites(plans: HookInstallPlan[]): { writes: PlannedWrite[]; installedPaths: string[] } {
  const writes = new Map<string, PlannedWrite>()
  const installedPaths = new Set<string>()
  for (const plan of plans) {
    for (const path of plan.installedPaths) installedPaths.add(path)
    for (const write of plan.writes) {
      const existing = writes.get(write.path)
      if (existing && (!existing.contents.equals(write.contents)
        || existing.defaultMode !== write.defaultMode || existing.forceMode !== write.forceMode)) {
        throw new Error(`hook installation planned conflicting writes to ${write.path}`)
      }
      writes.set(write.path, write)
    }
  }
  return { writes: [...writes.values()], installedPaths: [...installedPaths] }
}

/**
 * Stage every replacement in its destination directory before publishing any
 * of them. If publication fails, restore the exact bytes and mode captured at
 * the start of the transaction. A concurrent editor is detected before the
 * first rename so CodeTruss never knowingly overwrites a newer hook config.
 */
export async function commitPlannedWrites(writes: PlannedWrite[]): Promise<void> {
  const snapshots = new Map<string, FileSnapshot>()
  const temporaryFiles = new Map<string, string>()
  const committed: PlannedWrite[] = []
  for (const write of writes) snapshots.set(write.path, await snapshotFile(write.path))
  try {
    for (const write of writes) {
      const snapshot = snapshots.get(write.path)!
      const mode = write.forceMode ?? snapshot.mode ?? write.defaultMode
      temporaryFiles.set(write.path, await writeTemporaryFile(write, mode))
    }
    for (const snapshot of snapshots.values()) {
      if (!await snapshotStillMatches(snapshot)) {
        throw new Error(`hook file changed during installation and was left untouched: ${snapshot.path}`)
      }
    }
    for (const write of writes) {
      await rename(temporaryFiles.get(write.path)!, write.path)
      temporaryFiles.delete(write.path)
      committed.push(write)
    }
  } catch (error) {
    const rollbackErrors: string[] = []
    for (const write of committed.reverse()) {
      const snapshot = snapshots.get(write.path)!
      try {
        if (!snapshot.exists) {
          await rm(write.path, { force: true })
        } else {
          const restore = plannedWrite(write.path, snapshot.contents!, snapshot.mode!, snapshot.mode!)
          const temporary = await writeTemporaryFile(restore, snapshot.mode!)
          await rename(temporary, write.path)
        }
      } catch (rollbackError) {
        rollbackErrors.push(`${write.path}: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`)
      }
    }
    if (rollbackErrors.length) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}; hook rollback also failed: ${rollbackErrors.join('; ')}`)
    }
    throw error
  } finally {
    await Promise.all([...temporaryFiles.values()].map((path) => rm(path, { force: true }).catch(() => undefined)))
  }
}
