import { moveSecretToEnvFix, untrackEnvFileFix } from './fixes'
import { incompleteAnalyzerOutput, measuredCoverage, type Analyzer, type AnalyzerFinding } from './types'

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

/** {@link SECRET_PATTERNS} as global matchers, for replacing every occurrence. */
const REDACTION_PATTERNS = SECRET_PATTERNS.map(({ name, re }) => ({
  name,
  re: new RegExp(re.source, `${re.flags}g`),
}))

/**
 * Replace anything credential-shaped in free text with its credential TYPE.
 *
 * This module's contract is that values never leave it. Text harvested from the
 * repository and quoted onto a signed receipt is bound by the same contract even
 * when another pass harvests it — a `codetruss-ignore` reason runs to the end of
 * its physical line, so on a one-line file the marker swallows whatever follows
 * it. Redacting is preferred to dropping the text: the reason is the entire
 * evidentiary output of the marker, and a receipt that says only "dismissed" has
 * lost the thing that made the dismissal auditable.
 */
export function redactSecrets(text: string): string {
  let out = text
  for (const { name, re } of REDACTION_PATTERNS) out = out.replace(re, `[redacted ${name}]`)
  return out
}

const SKIP_FILES = /(\.env\.example|\.md|\.lock|package-lock\.json|pnpm-lock\.yaml)$/i
/**
 * A line that announces itself as documentation or a template. Matching here
 * skips the line in silence.
 *
 * The word markers are TOKEN-ANCHORED. Unanchored they matched inside any
 * alphanumeric run, and `xxx` is three characters: a random 2048-bit credential
 * contains one about 4% of the time, so one line in twenty-five carrying a real
 * key was dropped without a finding of any kind. The structural markers
 * (`<PLACEHOLDER>`, `${VAR}`) are punctuation-delimited already and stay as
 * they are, and `your-`/`your_` anchors on its left only because the token
 * continues past it (`your_api_key`).
 */
const PLACEHOLDER = new RegExp(
  [
    '<[^>]+>',
    '\\$\\{',
    '(?<![A-Za-z0-9])your[-_]',
    '(?<![A-Za-z0-9])(?:example|placeholder|changeme|dummy|x{3,})(?![A-Za-z0-9])',
  ].join('|'),
  'i',
)
/**
 * A placeholder marker that OPENS a block: `example: {`, `@ApiProperty({`.
 *
 * PLACEHOLDER is evaluated per line, so a Swagger `@ApiProperty({ example: {`
 * two lines above a sample credential was invisible and the sample was reported
 * as a committed leak. The block is closed by the first non-blank line indented
 * no further than the opener — cheap, deterministic, and it cannot run away.
 */
const PLACEHOLDER_BLOCK_OPEN = /[{[(]\s*$/
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
 *
 * EVERY alternative is token-anchored, the pre-existing ones included. This is
 * the load-bearing property of the whole pattern and it was measured: `xxx+`
 * unanchored and case-insensitive matches 18 of 400 real `generateKeyPairSync`
 * RSA-2048 PEM bodies (4.5%) on collisions like `XXX`, `xXx`, `XxX`. Everything
 * routed here lands on `severity: INFO`, `impactScore: 5`, "No action needed."
 * — so an unanchored alternative does not merely lose a finding, it publishes a
 * reassurance about a leaked key. Anchored, the same 400 keys produce zero.
 *
 * Adding an alternative means re-running that measurement. A three-character
 * alternative is a liability even anchored; prefer longer, delimiter-bearing
 * forms (`test-key`, `not-a-real`) over bare words.
 */
export const FAKE_LITERAL_VALUE = new RegExp(
  '(?<![A-Za-z0-9])(?:'
  + 'example|sample|dummy|fake|placeholder|changeme|mock|stub'
  + '|test[-_]?(?:key|secret)|not[-_]?a[-_]?real'
  + '|your[-_]?(?:key|token|secret)|abc123|x{3,}'
  + ')(?![A-Za-z0-9])',
  'i',
)

/**
 * The literal a match assigns, for placeholder judgement.
 *
 * `match[0]` for the fuzzy assignment patterns spans the KEY as well as the
 * value — `examplePassword: "<a real secret>"` — so judging it let an identifier
 * bless the credential sitting beside it. Judge the quoted literal when the
 * pattern captured one; patterns that match a bare credential token (an AWS key
 * in YAML) carry no quotes and are judged whole.
 */
function placeholderSubject(credentialType: string, matched: string): string | null {
  // A private key's "value" is a base64 PEM body: a high-entropy blob, not a
  // string that can announce itself as fake. Excluded by construction rather
  // than by trusting the anchoring above to hold for 1,700 random characters.
  if (credentialType === 'Private key block') return null
  return /['"`]([^'"`]*)['"`]/.exec(matched)?.[1] ?? matched
}

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
    // 50 was hit exactly on a 300k-LOC repository, which made every count
    // anyone quoted a truncated prefix AND — because a truncated required pass
    // is not authoritative — voided all five score axes over a benign cap.
    // 500 is above any real repository's genuine count while still bounding a
    // pathological tree.
    const findingLimit = 500
    /**
     * Every credential-shaped line this pass matched, including the ones the cap
     * left no room to report. Counting past the cap is the whole point: 500
     * reported findings could mean 500 secrets or 5,000, and a consumer that
     * cannot tell them apart has to treat both as a total loss.
     *
     * This is why the sweep no longer stops at the cap. Reading on costs one
     * more regex pass over a tree the analyzer already sweeps whenever the cap
     * is NOT hit, and it buys the difference between "we showed you 500 of 512"
     * and "we showed you 500 of 9,000" — which is the difference between an
     * immaterial cap and a security score nobody should publish.
     */
    let matches = 0
    /**
     * Building the finding is deferred because a reported secret carries a
     * generated fix diff, and generating one for a finding the cap will discard
     * is pure waste.
     */
    const report = (build: () => AnalyzerFinding): void => {
      matches++
      if (findings.length < findingLimit) findings.push(build())
    }
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
      /** Indent column of the open placeholder block, or -1 when none is open. */
      let placeholderBlock = -1
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const indent = line.length - line.trimStart().length
        const blank = line.trim() === ''
        // A blank line ends nothing; the first non-blank line at or left of the
        // opener's indent does.
        if (placeholderBlock >= 0 && !blank && indent <= placeholderBlock) placeholderBlock = -1
        const declaresPlaceholder = PLACEHOLDER.test(line)
        const inPlaceholderBlock = placeholderBlock >= 0
        // Only the OUTERMOST block is tracked; anything nested inside it is
        // more deeply indented and therefore already covered.
        if (placeholderBlock < 0 && declaresPlaceholder && PLACEHOLDER_BLOCK_OPEN.test(line)) {
          placeholderBlock = indent
        }
        if (declaresPlaceholder || inPlaceholderBlock) continue
        for (const { name, re } of SECRET_PATTERNS) {
          const match = line.match(re)
          if (!match) continue
          if (RUNTIME_CREDENTIAL_REFERENCE.test(match[0])) continue
          const subject = placeholderSubject(name, match[0])
          if (subject !== null && FAKE_LITERAL_VALUE.test(subject)) {
            report(() => ({
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
            }))
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
            report(() => ({
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
            }))
            break
          }
          if (!isEnvFile && (messageString || (isTestContext && TEST_DOWNGRADEABLE.has(name)))) {
            report(() => ({
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
            }))
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
            report(() => {
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
              return {
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
              }
            })
          }
          break // one finding per line
        }
      }
    }
    // Reaching the cap exactly is not a loss — every match was reported — so
    // only an overflow truncates. What it reports is measurable: the share of
    // this repository's real matches the reader can actually see.
    return matches > findingLimit
      ? incompleteAnalyzerOutput(findings, {
          truncated: true,
          coverageRatio: measuredCoverage(findings.length, matches),
          detail: `Secret scanning reported ${findings.length} of ${matches} credential matches; the ${findingLimit}-finding cap dropped the rest.`,
          metrics: { matches, reported: findings.length, findingLimit },
        })
      : findings
  },
}
