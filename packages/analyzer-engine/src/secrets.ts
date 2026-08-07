import { moveSecretToEnvFix, untrackEnvFileFix } from './fixes'
import { incompleteAnalyzerOutput, type Analyzer, type AnalyzerFinding } from './types'

/**
 * Defensive secret-exposure detection: flags credentials that appear to be
 * committed so the owner can rotate them. Values are NEVER included in
 * findings — only the location and the credential type.
 *
 * Length floors are tuned to real credential formats so short test strings
 * (e.g. "sk-ant-abc123-...") do not masquerade as production keys.
 */
const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'Stripe live secret key', re: /\bsk_live_[A-Za-z0-9]{24,}\b/ },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{80,}\b/ },
  { name: 'OpenAI API key', re: /\bsk-(?!ant-)[A-Za-z0-9_-]{40,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Generic password assignment', re: /(?:password|passwd|secret)\s*[:=]\s*['"][^'"]{8,}['"]/i },
  { name: 'Database URL with credentials', re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/([^\s'":@/]+):([^\s'"@]+)@([^\s'"/]+)/ },
]

const SKIP_FILES = /(\.env\.example|\.md|\.lock|package-lock\.json|pnpm-lock\.yaml)$/i
const PLACEHOLDER = /(example|placeholder|your[-_]|xxx|changeme|dummy|<[^>]+>|\$\{)/i
/**
 * Runtime credential REFERENCES — `process.env.X`, `{{...}}`, `${VAR}`, `ENV[]`.
 * This is how a credential is *supposed* to be written, so it is skipped in
 * silence; annotating correct code would be noise.
 */
const RUNTIME_CREDENTIAL_REFERENCE = /(\{\{|\$\{|process\.env|os\.environ|os\.getenv|\bgetenv\b|ENV\[)/i

/**
 * Literals that announce themselves as fake. Skipping these silently is
 * correct, but a silent skip looks exactly like a scanner that detects nothing
 * — which is what a developer concludes when they test it with a dummy key.
 * Reported at INFO so the skip is visible and explained.
 */
const FAKE_LITERAL_VALUE =
  /(example|sample|dummy|fake|placeholder|changeme|your[-_]?(key|token|secret)|abc123|xxx+)/i

/** SCREAMING_SNAKE values are constant identifiers, not credentials —
 *  `UPDATE_PASSWORD = 'UPDATE_PASSWORD'` is an enum member. */
const CONSTANT_IDENTIFIER_VALUE = /^[A-Z0-9]+(_[A-Z0-9]+)+$/

/** Dev/CI dummy hosts — credentials pointing here are not real secrets. */
const DUMMY_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', 'host.docker.internal'])

/** Test/fixture locations: findings here are downgraded, not silenced.
 *  Covers JS (.test./.spec., __tests__/), Go (_test.go), Python (test_*.py,
 *  *_test.py), and Ruby (spec/, *_spec.rb) conventions. */
const TEST_PATH_RE =
  /(^|\/)(tests?|__tests__|__mocks__|fixtures|spec)\/|\.(test|spec)\.|_(test|spec)\.(go|py|rb|exs?)$|(^|\/)(test|spec)_[^/]+\.(py|rb)$/

/**
 * Only the fuzzy generic-password pattern is eligible for the test-fixture
 * downgrade: every other pattern matches an unambiguous production credential
 * format, which is a real leak even when pasted into a test file.
 */
const TEST_DOWNGRADEABLE = new Set(['Generic password assignment'])

/**
 * Database seed / fixture scripts. Their credentials are deliberate, documented
 * dev defaults, so "treat as compromised, rotate immediately" is the wrong
 * instruction — the real risk is the seed path reaching a production database.
 */
const SEED_PATH_RE = /(^|\/)(seed|seeds|seeders?)(\/|\.|$)|(^|\/)seed[-_.][^/]*$/i

export const secretsAnalyzer: Analyzer = {
  id: 'secrets',
  name: 'Exposed Secrets',
  description: 'Detects credentials committed to the repository (defensive; values are never reported).',
  async run(index) {
    const findings: AnalyzerFinding[] = []
    const findingLimit = 50
    // Where a move-to-env fix appends its variable. Undefined means the file
    // does not exist, which the diff renders as a new-file hunk.
    const envExample = index.files.find((file) => file.path === '.env.example')?.content
    const envExampleLines = envExample === undefined || envExample === null
      ? undefined
      : envExample.length === 0 ? 0 : envExample.replace(/\n$/, '').split('\n').length

    for (const file of index.files) {
      // Generated/minified files are excluded from every OTHER analyzer to stop
      // machine-written output producing spurious quality findings. That
      // exclusion must never extend to credentials: a leaked key is a leak no
      // matter which tool emitted the line, and a `DO NOT EDIT` banner would
      // otherwise be a one-comment bypass of the whole secret scanner.
      const content = file.content ?? file.excludedContent
      if (!content || SKIP_FILES.test(file.path)) continue
      /** Machine-written text: read for credentials, but never hand-edited. */
      const isGeneratedFile = !file.content
      const isTestContext = TEST_PATH_RE.test(file.path)
      const isSeedScript = SEED_PATH_RE.test(file.path)
      const lines = content.split('\n')
      for (let i = 0; i < lines.length && findings.length < findingLimit; i++) {
        const line = lines[i]
        if (PLACEHOLDER.test(line)) continue
        for (const { name, re } of SECRET_PATTERNS) {
          const match = line.match(re)
          if (!match) continue
          if (RUNTIME_CREDENTIAL_REFERENCE.test(match[0])) continue
          if (FAKE_LITERAL_VALUE.test(match[0])) {
            findings.push({
              category: 'SECURITY_HYGIENE',
              severity: 'INFO',
              title: `Credential-shaped placeholder ignored in ${file.path.split('/').pop()}`,
              description: `Line ${i + 1} of ${file.path} matches a ${name} pattern, but the value announces itself as a placeholder, so it is NOT reported as a leak. Shown only to confirm the scanner read this line — a real credential in the same position would be reported.`,
              filePath: file.path,
              line: i + 1,
              suggestion: 'No action needed. This entry exists so a deliberate skip is never mistaken for a missed detection.',
              impactScore: 5,
              effort: 'low',
              metadata: { credentialType: name, placeholder: true },
            })
            break
          }
          // A credential committed to source is a single token. Internal
          // whitespace means the value is display text — a validation message,
          // an i18n string, a UI label — which nearly every repo has under a
          // `password:` key. Reported HIGH it would say "rotate immediately"
          // about a translation, and drag the security score with it.
          let messageString = false
          if (name === 'Generic password assignment') {
            const value = /['"]([^'"]+)['"]/.exec(match[0])?.[1]
            if (value && CONSTANT_IDENTIFIER_VALUE.test(value)) continue
            if (value && /\s/.test(value)) messageString = true
          }
          if (name === 'Database URL with credentials') {
            const hostPort = match[3]
            const host = hostPort.replace(/:\d+$/, '').replace(/^\[|\]$/g, '')
            // localhost/CI dummy hosts are not leaks; default credentials
            // (postgres:postgres, admin:admin) on a real host still are.
            if (DUMMY_HOSTS.has(host)) continue
          }
          // Committed .env files always escalate, even under tests/ or a seed path.
          const isEnvFile = /(^|\/)\.env/.test(file.path)
          const baseName = file.path.split('/').pop()
          if (!isEnvFile && !messageString && isSeedScript && TEST_DOWNGRADEABLE.has(name)) {
            findings.push({
              category: 'SECURITY_HYGIENE',
              severity: 'MEDIUM',
              title: `Seed-script credential in ${baseName}`,
              description: `Line ${i + 1} of ${file.path} sets a ${name} inside a database seed script. Seed defaults are usually intentional, but anyone who can read the repository knows this login, so it becomes a real account the moment seeding runs anywhere reachable.`,
              filePath: file.path,
              line: i + 1,
              suggestion: 'Confirm this seed cannot execute against a production or shared database (guard it on NODE_ENV, keep it out of deploy and migration steps), and generate the value at runtime instead of committing it.',
              impactScore: 45,
              effort: 'low',
              metadata: { credentialType: name, seedScript: true },
            })
            break
          }
          if (!isEnvFile && (messageString || (isTestContext && TEST_DOWNGRADEABLE.has(name)))) {
            findings.push({
              category: 'SECURITY_HYGIENE',
              severity: 'LOW',
              title: messageString
                ? `Message text under a credential-shaped key in ${baseName}`
                : `Test fixture resembling a secret: ${name} in ${baseName}`,
              description: messageString
                ? `Line ${i + 1} of ${file.path} assigns a credential-shaped key a value containing spaces, which reads as display text (a validation message, translation, or label) rather than a credential. Reported for awareness only — confirm no real passphrase was pasted here.`
                : `Line ${i + 1} of ${file.path} contains a value shaped like a ${name}. It sits in test/fixture code and does not match a production key format, so it is most likely a fixture — but confirm no real credential was pasted.`,
              filePath: file.path,
              line: i + 1,
              suggestion: messageString
                ? 'No action needed if this is user-facing copy. If a real passphrase was pasted here, rotate it and move it to environment configuration.'
                : 'Use an obviously fake placeholder (e.g. "test-not-a-real-key") so scanners and reviewers can dismiss it at a glance.',
              impactScore: messageString ? 10 : 25,
              effort: 'low',
              metadata: { credentialType: name, testContext: isTestContext, messageString },
            })
          } else {
            // A concrete fix only where the evidence determines one: a tracked
            // .env is untracked wholesale, and a source assignment becomes an
            // environment read. Anything else (a key inside a call, a private
            // key block, an unsupported language) keeps the prose suggestion.
            //
            // A generated file is read here (`content` came from
            // excludedContent) precisely so its credentials are not exempt —
            // but its LINE is not the place to fix them. The next generation
            // overwrites any edit; the credential has to leave the generator's
            // input. So the leak is reported and the diff is withheld.
            const fix = isEnvFile
              ? untrackEnvFileFix(file.path)
              : isGeneratedFile
                ? undefined
                : moveSecretToEnvFix({
                    filePath: file.path,
                    line: i + 1,
                    lineText: line,
                    credentialType: name,
                    envExampleLines,
                  })
            findings.push({
              category: 'SECURITY_HYGIENE',
              severity: isEnvFile ? 'CRITICAL' : 'HIGH',
              title: `Possible ${name} committed in ${file.path.split('/').pop()}`,
              description: `Line ${i + 1} of ${file.path} appears to contain a ${name}. Committed credentials should be treated as compromised.`,
              filePath: file.path,
              line: i + 1,
              suggestion: 'Rotate this credential immediately, move it to environment configuration, and add the file to .gitignore. Consider a pre-commit secret scanner.',
              ...(fix ? { fix } : {}),
              impactScore: 95,
              effort: 'low',
              metadata: { credentialType: name },
            })
          }
          break // one finding per line
        }
      }
    }
    return findings.length >= findingLimit
      ? incompleteAnalyzerOutput(findings, {
          truncated: true,
          detail: `Secret scanning stopped after ${findingLimit} matches.`,
          metrics: { matches: findings.length, findingLimit },
        })
      : findings
  },
}
