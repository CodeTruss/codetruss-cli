import { PINNED_GRAMMAR_PACKS } from './grammar-pack-manifest.js'
import {
  grammarPackDir,
  inspectGrammarPack,
  installGrammarPack,
  resolveGrammarOrigin,
  uninstallGrammarPack,
} from './grammar-pack.js'

/**
 * `codetruss grammars` — the only surface that downloads anything at analysis
 * time's expense but never during analysis itself.
 *
 * Installation is a separate, explicit act for two reasons. It is a network
 * operation, and a tool that promises local-first analysis must not reach out
 * mid-review; and it puts executable code on the machine, which is a decision a
 * person makes, not a side effect of running a scan. Nothing here is invoked
 * implicitly, and no other command falls back to it.
 */

function packSummary(bytes: number): string {
  return `${(bytes / 1024).toFixed(0)} KB`
}

export async function runGrammarsCommand(
  action: string,
  name: string | undefined,
  write: (text: string) => void = (text) => process.stdout.write(text),
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  if (action === 'list') {
    write('Available grammar packs:\n')
    for (const pack of PINNED_GRAMMAR_PACKS) {
      const bytes = pack.files.reduce((sum, file) => sum + file.bytes, 0)
      write(
        `  ${pack.name}-${pack.version}  ${packSummary(bytes)}  `
        + `${pack.runtime.package}@${pack.runtime.version} + ${pack.grammar.package}@${pack.grammar.version}\n`,
      )
    }
    write(`\nInstall with: codetruss grammars install ${PINNED_GRAMMAR_PACKS[0]?.name ?? 'python'}\n`)
    return 0
  }

  if (action === 'status') {
    let allHealthy = true
    for (const pack of PINNED_GRAMMAR_PACKS) {
      const state = await inspectGrammarPack(pack.name, env)
      if (state.status === 'verified') {
        write(`${pack.name}-${pack.version}: installed and verified\n  ${state.dir}\n`)
      } else if (state.status === 'absent') {
        allHealthy = false
        write(
          `${pack.name}-${pack.version}: not installed\n`
          + `  ${pack.language} is skipped locally and disclosed as such on every receipt.\n`
          + `  Install with: codetruss grammars install ${pack.name}\n`,
        )
      } else {
        allHealthy = false
        // A failed pack is louder than a missing one on purpose: absent is a
        // choice, failed means the bytes on disk are not what this CLI published.
        write(
          `${pack.name}-${pack.version}: FAILED VERIFICATION — not loaded\n`
          + `  ${state.reason}\n`
          + `  ${state.dir}\n`
          + `  Reinstall with: codetruss grammars install ${pack.name}\n`,
        )
      }
    }
    return allHealthy ? 0 : 1
  }

  if (action === 'install') {
    if (!name) throw new Error(`grammars install requires a pack name (${PINNED_GRAMMAR_PACKS.map((pack) => pack.name).join(', ')})`)
    const origin = resolveGrammarOrigin(env.CODETRUSS_DEV_GRAMMAR_ORIGIN)
    const result = await installGrammarPack(name, env)
    if (result.alreadyInstalled) {
      write(`${result.pack.name}-${result.pack.version} is already installed and verified.\n  ${result.dir}\n`)
      return 0
    }
    write(
      `Installed ${result.pack.name}-${result.pack.version} (${packSummary(result.bytes)}) from ${origin}.\n`
      + `  ${result.dir}\n`
      + `  ${result.pack.runtime.package}@${result.pack.runtime.version}, `
      + `${result.pack.grammar.package}@${result.pack.grammar.version}\n`
      + `  Every artifact matched the SHA-256 pinned in this CLI, and is re-checked on each load.\n`
      + `  ${result.pack.language} now runs the full security rule pack locally.\n`,
    )
    return 0
  }

  if (action === 'uninstall') {
    if (!name) throw new Error('grammars uninstall requires a pack name')
    const result = await uninstallGrammarPack(name, env)
    write(
      result.removed
        ? `Removed ${result.pack.name}-${result.pack.version}. ${result.pack.language} is skipped locally again.\n`
        : `${result.pack.name}-${result.pack.version} was not installed (${grammarPackDir(result.pack, env)}).\n`,
    )
    return 0
  }

  throw new Error('grammars requires list, status, install, or uninstall')
}
