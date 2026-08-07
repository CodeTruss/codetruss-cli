import { isAbsolute, resolve } from 'node:path'
import { runGitText } from './git-process.js'

const MARKER = 'codetruss-agent-guard'
export const CODETRUSS_PRE_COMMIT_ENV = 'CODETRUSS_INTERNAL_PRE_COMMIT'
export const BEGIN_MARKER = `# ${MARKER}:begin`
export const END_MARKER = `# ${MARKER}:end`

export function effectivePreCommitPath(root: string): string {
  const raw = runGitText(root, ['rev-parse', '--git-path', 'hooks/pre-commit']).trim()
  if (!raw) throw new Error('Git did not return an effective pre-commit hook path')
  return isAbsolute(raw) ? resolve(raw) : resolve(root, raw)
}

export function stripCodeTrussPreCommit(existing: string): string {
  const begin = existing.indexOf(BEGIN_MARKER)
  if (begin >= 0) {
    const lineStart = existing.lastIndexOf('\n', begin - 1) + 1
    const end = existing.indexOf(END_MARKER, begin)
    if (end < 0) throw new Error('existing CodeTruss pre-commit block is missing its end marker')
    const lineEnd = existing.indexOf('\n', end)
    return `${existing.slice(0, lineStart)}${lineEnd < 0 ? '' : existing.slice(lineEnd + 1)}`.replace(/\n{3,}$/g, '\n')
  }
  const legacy = existing.indexOf(`# ${MARKER}`)
  if (legacy >= 0) {
    const lineStart = existing.lastIndexOf('\n', legacy - 1) + 1
    return existing.slice(0, lineStart).replace(/\n{3,}$/g, '\n')
  }
  return existing
}

export function preCommitBlock(): string {
  return `${BEGIN_MARKER}
ROOT="$(git -c core.longpaths=true rev-parse --show-toplevel 2>/dev/null)" || exit 0
CODETRUSS_STATUS=0
if [ -x "$ROOT/node_modules/.bin/codetruss" ]; then
  ${CODETRUSS_PRE_COMMIT_ENV}=1 "$ROOT/node_modules/.bin/codetruss" review --staged --task "pre-commit" || CODETRUSS_STATUS=$?
else
  ${CODETRUSS_PRE_COMMIT_ENV}=1 codetruss review --staged --task "pre-commit" || CODETRUSS_STATUS=$?
fi
case "$CODETRUSS_STATUS" in
  0) ;;
  1)
    printf '%s\n' 'CodeTruss REVIEW_REQUIRED: receipt created; commit allowed for human review.' >&2
    ;;
  2)
    printf '%s\n' 'CodeTruss FAILED: commit blocked. Review the receipt before retrying.' >&2
    exit 2
    ;;
  *)
    printf '%s\n' "CodeTruss could not produce a trustworthy receipt (exit $CODETRUSS_STATUS); commit blocked." >&2
    exit "$CODETRUSS_STATUS"
    ;;
esac
${END_MARKER}`
}
