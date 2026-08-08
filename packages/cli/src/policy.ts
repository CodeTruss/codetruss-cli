import { minimatch } from 'minimatch'
import type { ScopeClassification } from './types.js'

export function classifyPath(path: string, oldPath: string | undefined, allow: string[], deny: string[]): ScopeClassification {
  const one = (candidate: string): ScopeClassification => {
    const normalized = candidate.replaceAll('\\', '/').replace(/^\.\//, '')
    if (deny.some((pattern) => minimatch(normalized, pattern, { dot: true }))) return 'denied'
    if (allow.some((pattern) => minimatch(normalized, pattern, { dot: true }))) return 'allowed'
    return 'unexpected'
  }
  const current = one(path)
  if (!oldPath) return current
  const previous = one(oldPath)
  // `inferred` is never produced here; scope inference runs over the whole
  // changed set afterwards. The rank still orders it, so a rename that touches
  // an inferred origin can never be reported as plainly allowed.
  const rank: Record<ScopeClassification, number> = { allowed: 0, inferred: 1, unexpected: 2, denied: 3 }
  return rank[previous] > rank[current] ? previous : current
}

/**
 * A predicate for `.codetruss.yml` `exclude` globs, normalizing paths exactly
 * the way classifyPath does so a glob that means one thing for scope cannot
 * quietly mean another for analysis.
 *
 * Returns a predicate that is always false for an empty list, so the indexer
 * takes no per-file cost in the overwhelmingly common case.
 */
export function excludeMatcher(exclude: string[]): ((path: string) => boolean) | undefined {
  if (!exclude.length) return undefined
  return (path: string) => {
    const normalized = path.replaceAll('\\', '/').replace(/^\.\//, '')
    return exclude.some((pattern) => minimatch(normalized, pattern, { dot: true }))
  }
}

const SENSITIVE: Array<[string, string]> = [
  ['.codetruss.yml', 'policy'], ['**/.gitignore', 'vcs'], ['**/.gitattributes', 'vcs'],
  ['.github/workflows/**', 'ci'], ['.gitlab-ci.yml', 'ci'], ['.circleci/**', 'ci'], ['.buildkite/**', 'ci'], ['Jenkinsfile', 'ci'], ['azure-pipelines.yml', 'ci'],
  ['**/Dockerfile', 'container'], ['**/Dockerfile.*', 'container'], ['**/Containerfile', 'container'], ['**/docker-compose*.yml', 'container'], ['**/docker-compose*.yaml', 'container'],
  ['**/*.tf', 'iac'], ['**/*.tfvars', 'iac'], ['**/Pulumi.yaml', 'iac'], ['**/serverless.y*ml', 'iac'],
  ['**/migrations/**', 'migration'], ['db/migrate/**', 'migration'],
  ['Procfile', 'deploy'], ['vercel.json', 'deploy'], ['netlify.toml', 'deploy'], ['fly.toml', 'deploy'], ['app.yaml', 'deploy'],
  ['**/.env', 'secrets'], ['**/.env.*', 'secrets'], ['**/*.pem', 'secrets'], ['**/id_rsa*', 'secrets'], ['**/id_ed25519*', 'secrets'],
]

const DEPENDENCY_NAMES = new Set([
  'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb',
  'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'requirements.txt', 'poetry.lock', 'Pipfile', 'Pipfile.lock',
  'pyproject.toml', 'Gemfile', 'Gemfile.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'composer.json', 'composer.lock',
])

export function sensitiveCategory(path: string): string | undefined {
  const normalized = path.replaceAll('\\', '/')
  return SENSITIVE.find(([pattern]) => minimatch(normalized, pattern, { dot: true }))?.[1]
}

export function isDependencyFile(path: string): boolean {
  return DEPENDENCY_NAMES.has(path.split('/').pop() ?? path)
}
