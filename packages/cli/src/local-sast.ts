import type { AnalyzerFinding, AnalyzerPass, RepoIndex } from '@codetruss/analyzer-engine'
import { scanFiles, type ScanInput } from '@codetruss/analyzer-engine/security/engine'
import { zeroDependencyJsParser } from '@codetruss/analyzer-engine/security/js-parse/index'
import { mapSastFinding } from '@codetruss/analyzer-engine/security/finding-map'
import { CLI_SAST_RULE_IDS } from '@codetruss/analyzer-engine/security/local-profile'
import { sastLanguageForPath } from '@codetruss/analyzer-engine/security/lang'

/**
 * The CLI's local security pass.
 *
 * Same engine, same rules, same taint solver as the hosted audit — behind a
 * zero-dependency parser instead of 6 MB of WASM grammars, and restricted to the
 * rule subset that has been differentially validated against the hosted parser
 * at zero false positives.
 *
 * This is NOT one of the 13 registry analyzers. Keeping it a separate pass is
 * what lets the receipt keep saying "13 deterministic registry analyzers"
 * truthfully while naming this pass and its limits alongside them.
 */
export const LOCAL_SAST_PASS_ID = 'local-sast'

/**
 * Declaration files (`*.d.ts`) carry no executable code, so no rule can fire in
 * them. Excluding them keeps the parser's coverage number honest instead of
 * reporting "degraded" for files where degradation is meaningless.
 */
function isDeclarationFile(path: string): boolean {
  return /\.d\.[cm]?ts$/i.test(path)
}

/** Production JS-family source the local parser can analyze. */
export function localSastInputs(index: RepoIndex): ScanInput[] {
  const inputs: ScanInput[] = []
  for (const file of index.files) {
    if (!file.content) continue
    // Mirrors the hosted selection: security rules over vendored, generated or
    // test files are almost all false positives — tests exercise code, they are
    // not the attack surface.
    if (file.kind === 'vendored' || file.kind === 'generated' || file.kind === 'test') continue
    if (isDeclarationFile(file.path)) continue
    const language = sastLanguageForPath(file.path)
    if (!language || !zeroDependencyJsParser.languages.has(language)) continue
    inputs.push({ filePath: file.path, content: file.content })
  }
  // Deterministic order so findings and diagnostics are identical run to run.
  inputs.sort((a, b) => a.filePath.localeCompare(b.filePath))
  return inputs
}

export interface LocalSastResult {
  findings: AnalyzerFinding[]
  pass: AnalyzerPass
}

export async function runLocalSast(index: RepoIndex): Promise<LocalSastResult> {
  const inputs = localSastInputs(index)
  if (inputs.length === 0) {
    return {
      findings: [],
      pass: {
        id: LOCAL_SAST_PASS_ID,
        result: {
          findings: [],
          complete: true,
          metrics: { inputFiles: 0, filesScanned: 0, filesSkipped: 0, rules: CLI_SAST_RULE_IDS.size },
        },
      },
    }
  }

  try {
    const result = await scanFiles(inputs, zeroDependencyJsParser, { ruleIds: CLI_SAST_RULE_IDS })
    const diagnostics = result.diagnostics
    // A file the parser could not read is coverage lost, and the receipt has to
    // say so rather than let silence read as "nothing found there".
    const truncated =
      diagnostics.filesSkipped > 0 || diagnostics.truncatedFiles > 0 || diagnostics.findingsTruncated
    const findings = result.findings.map((finding) => ({
      ...mapSastFinding(finding),
      analyzerId: LOCAL_SAST_PASS_ID,
    }))
    return {
      findings,
      pass: {
        id: LOCAL_SAST_PASS_ID,
        result: {
          findings,
          complete: !truncated && diagnostics.degradedLanguages.length === 0,
          truncated,
          detail: truncated
            ? `${diagnostics.filesSkipped} file(s) could not be parsed locally and were not analyzed`
            : undefined,
          metrics: {
            inputFiles: diagnostics.inputFiles,
            filesScanned: diagnostics.filesScanned,
            filesSkipped: diagnostics.filesSkipped,
            rules: CLI_SAST_RULE_IDS.size,
          },
        },
      },
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    return {
      findings: [],
      pass: { id: LOCAL_SAST_PASS_ID, result: { findings: [], complete: false, detail }, error: detail },
    }
  }
}
