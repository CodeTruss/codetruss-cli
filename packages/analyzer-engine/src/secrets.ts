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
 * PUBLISHABLE CLIENT IDENTIFIERS — credentials whose exposure is by design.
 *
 * Some credential formats are not secrets at all. A Firebase **web** `apiKey`, a
 * Google Maps browser key: these are compiled into the client bundle, Google
 * documents them as public identifiers, and what protects the project is
 * Security Rules, App Check and per-key restrictions — never keeping the value
 * out of the repository. Reporting one as a committed credential is wrong, and
 * "treat as compromised, rotate immediately" is wrong advice about it.
 *
 * A publishable identifier is recognised from the credential TYPE plus its
 * surroundings, never from either alone. Only types listed here are eligible,
 * so the widest imaginable surroundings can never downgrade a Stripe live key or
 * a PEM block — and eligibility alone downgrades nothing, because a Google API
 * key is just as often a server key.
 */
const PUBLISHABLE_CREDENTIAL_TYPES = new Set(['Google API key'])

/**
 * Build-time variable prefixes that mean "this value ships to the browser".
 *
 * Vite, Next.js, Create React App, SvelteKit and Astro each inline variables
 * carrying these prefixes into the client bundle. The prefix is not a hint about
 * intent — it is the framework's guarantee that the value is already public to
 * every visitor, which is precisely why a committed one is not the leak.
 *
 * Four prefixes, each a documented convention of a major framework. Adding a
 * fifth widens what this analyzer will decline to escalate, so it is a
 * deliberate act and not a matter of being generous with synonyms.
 */
const PUBLISHABLE_ENV_BINDING = /\b((?:VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_)[A-Z0-9_]*)\s*[:=]/

/**
 * The keys a Firebase **web** app config carries beside `apiKey`, as object
 * keys (`authDomain:` or `"authDomain":`). Exact case, because that is how
 * Firebase documents and how its console emits them; a looser spelling buys
 * nothing and widens an exemption.
 */
const FIREBASE_WEB_CONFIG_KEYS = [
  'authDomain',
  'projectId',
  'storageBucket',
  'messagingSenderId',
  'appId',
  'databaseURL',
  'measurementId',
].map((key) => new RegExp(`['"]?${key}['"]?\\s*:`))

/**
 * How many of {@link FIREBASE_WEB_CONFIG_KEYS} must sit beside the key before
 * the object is a Firebase web config rather than something that merely holds
 * an `apiKey`. Three, because Firebase's console emits six or seven and the
 * threshold is the only thing standing between this exemption and a real key.
 */
const FIREBASE_WEB_CONFIG_SIBLINGS = 3

/**
 * Lines either side of the match that count as "beside" it. A web config is at
 * most eight keys, so its siblings are within eight lines of `apiKey` whether it
 * is written as one JSON line in a `.env` or spread down an `initializeApp({…})`
 * argument.
 */
const FIREBASE_WEB_CONFIG_WINDOW = 8

/**
 * The binding itself: `apiKey` assigned a value in Google's documented web-key
 * format, on ONE line. Both halves are load-bearing and neither is sufficient.
 */
const FIREBASE_WEB_API_KEY_BINDING = /['"]?apiKey['"]?\s*:\s*['"]AIza[0-9A-Za-z_-]{35}['"]/

/**
 * Whether this line's Google API key is a Firebase **web** config key.
 *
 * The second recogniser, and the one that does not need an environment file: the
 * config object itself. `initializeApp({ apiKey, authDomain, projectId, … })`
 * written straight into client source carries no `VITE_`-style name, and is the
 * same public identifier as the `.env` spelling.
 *
 * The predicate is a CONJUNCTION of three things, because the obvious shortcut —
 * exempting the key name `apiKey` — would hide real API keys in every codebase,
 * which is a far worse defect than the one it fixes:
 *
 *  1. the line binds the literal key `apiKey` (not `API_KEY`, not `googleKey`);
 *  2. its value is in Google's `AIza` + 35-character web-key format;
 *  3. at least {@link FIREBASE_WEB_CONFIG_SIBLINGS} of the Firebase config's
 *     other keys appear as object keys within
 *     {@link FIREBASE_WEB_CONFIG_WINDOW} lines.
 *
 * So it does NOT match: a Google API key under any other name; an `apiKey` whose
 * value is not `AIza…` (Stripe, OpenAI, an internal key); an `AIza…` Maps or
 * YouTube key that happens to sit near a Firebase block but is bound to its own
 * name; or a Firebase **admin** service-account JSON, whose keys are snake_case
 * and whose actual secret is a PEM block the private-key pattern still reports.
 */
export function isFirebaseWebApiKey(lines: readonly string[], index: number): boolean {
  if (!FIREBASE_WEB_API_KEY_BINDING.test(lines[index])) return false
  const context = lines
    .slice(Math.max(0, index - FIREBASE_WEB_CONFIG_WINDOW), index + FIREBASE_WEB_CONFIG_WINDOW + 1)
    .join('\n')
  let siblings = 0
  for (const key of FIREBASE_WEB_CONFIG_KEYS) if (key.test(context)) siblings += 1
  return siblings >= FIREBASE_WEB_CONFIG_SIBLINGS
}

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

/**
 * An identifier or slug broken into its lowercase words, so the two casings a
 * codebase uses for the same name compare equal: `IncorrectEmailPassword` and
 * `incorrect-email-password` both yield `[incorrect, email, password]`.
 */
function identifierWords(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // camelCase  -> camel Case
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2') // HTTPServer -> HTTP Server
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase())
}

/** True when `needle` appears as a contiguous run of words inside `haystack`. */
function isWordRun(needle: string[], haystack: string[]): boolean {
  if (needle.length === 0 || needle.length > haystack.length) return false
  for (let start = 0; start + needle.length <= haystack.length; start++) {
    if (needle.every((word, offset) => haystack[start + offset] === word)) return true
  }
  return false
}

/** The full identifier the pattern matched on, which spans further left than
 *  the match: `password` is where `IncorrectEmailPassword` ends, not begins. */
function assignedKey(line: string, matchIndex: number): string {
  const identifierChar = /[A-Za-z0-9_$]/
  let start = matchIndex
  while (start > 0 && identifierChar.test(line[start - 1])) start--
  let end = matchIndex
  while (end < line.length && identifierChar.test(line[end])) end++
  return line.slice(start, end)
}

/**
 * A value that merely spells out its own KEY — `IncorrectPassword =
 * "incorrect-password"`. Its words are a contiguous run of the key's words, so
 * it carries no information the identifier beside it did not already carry.
 * That is what an enum member, an error code, or an action constant looks like;
 * a credential is the opposite, a value the key cannot predict.
 *
 * The narrow shape matters. `password: "correct-horse-battery-staple"` is a
 * real passphrase in kebab case, so exempting kebab-case values wholesale would
 * suppress genuine leaks — the exemption has to be the RELATION to the key, not
 * the shape of the value. The relation is deliberately one-directional: words
 * dropped from the key are fine (`UserMissingPassword = "missing-password"`),
 * words ADDED to it are not, because added words are where entropy would live.
 *
 * A one-word restatement (`password = "password"`) stays reported. It is not an
 * enum member — it is a credential that happens to be worthless, and the two
 * are indistinguishable from the key alone.
 */
function restatesItsKey(line: string, matchIndex: number, value: string): boolean {
  const valueWords = identifierWords(value)
  return valueWords.length >= 2 && isWordRun(valueWords, identifierWords(assignedKey(line, matchIndex)))
}

/**
 * Prose quoting a credential pattern in order to describe it, rather than an
 * assignment that sets one.
 *
 * This scanner was run over its own source and reported three of its own
 * doc comments: the note on restatesItsKey, which quotes `password =
 * "password"` to explain why that shape stays reported, and two that cite
 * `AKIA1234567890ABCDEF` while explaining how fabricated keys are recognized.
 * CLI 0.2.57 failed its own gate on the first of them.
 *
 * A code span on a comment line is the shape, but it is NOT the exemption —
 * backticks alone would be a place to hide a live key. The exemption is that
 * the value is independently provable as not-a-credential, by one of two
 * anchors that already exist here and are already measured:
 *
 *  - {@link hasSyntheticSequence}: the body was typed, not generated. Eight
 *    consecutive stepping characters; 20,000 random bodies produce zero hits.
 *  - The one-word restatement from {@link restatesItsKey}: the value spells
 *    out its own key, so it carries no entropy the key did not already carry.
 *
 * Every other half stays reported, and each closes a different hole. A
 * commented-out assignment holding a real key (`// const apiKey =
 * "sk-live-…"`) has no code span. A template literal in executable code is not
 * on a comment line. A genuinely random value quoted in a comment satisfies
 * neither anchor.
 *
 * Comment detection is deliberately the unambiguous prefix only. Tracking open
 * block comments across lines would let a stray `/*` inside a string silence
 * every line after it, and a wrong answer here hides a credential.
 */
function documentsAnExample(line: string, match: RegExpMatchArray, subject: string | null): boolean {
  const matchIndex = match.index ?? 0
  const trimmed = line.trimStart()
  if (!trimmed.startsWith('*') && !trimmed.startsWith('//') && !trimmed.startsWith('#')) return false

  // Odd backtick count before the match means it opened inside a span; a
  // closing backtick after it means the span encloses the match.
  const openedBefore = (line.slice(0, matchIndex).match(/`/g) ?? []).length % 2 === 1
  if (!openedBefore || !line.slice(matchIndex + match[0].length).includes('`')) return false

  if (subject !== null && hasSyntheticSequence(subject)) return true

  const quoted = /['"]([^'"]+)['"]/.exec(match[0])?.[1]
  if (quoted === undefined) return false
  const valueWords = identifierWords(quoted)
  return valueWords.length === 1 && isWordRun(valueWords, identifierWords(assignedKey(line, matchIndex)))
}

/** Dev/CI dummy hosts — credentials pointing here are not real secrets. */
const DUMMY_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', 'host.docker.internal'])

/** Test/fixture locations: findings here are downgraded, not silenced.
 *  Covers JS (.test./.spec., __tests__/), Go (_test.go), Python (test_*.py,
 *  *_test.py), and Ruby (spec/, *_spec.rb) conventions. */
const TEST_PATH_RE =
  /(^|\/)(tests?|__tests__|__mocks__|fixtures|spec)\/|\.(test|spec)\.|_(test|spec)\.(go|py|rb|exs?)$|(^|\/)(test|spec)_[^/]+\.(py|rb)$/

/**
 * Only the fuzzy generic-password pattern is eligible for the SEED-script
 * downgrade: every other pattern matches an unambiguous production credential
 * format, which is a real leak even when pasted into a seed file.
 */
const TEST_DOWNGRADEABLE = new Set(['Generic password assignment'])

/**
 * Typed credential patterns that a test path may downgrade — but ONLY together
 * with {@link hasSyntheticSequence}, never on the path alone.
 *
 * The path is not evidence. A real key pasted into `checkout.e2e.ts` is exactly
 * the leak this analyzer exists to catch, and a path-only exemption wide enough
 * to clear a repository's secret-scanner fixtures would clear that too. So the
 * downgrade is a conjunction: the file has to be a test AND the value's body has
 * to be a hand-typed sequence rather than a random draw.
 *
 * Two patterns are deliberately absent:
 *  - **Database URL with credentials.** A production DSN pasted into a fixture
 *    is one of the commonest ways a live credential reaches a public repo, and
 *    the host in it is the thing at risk. Adjudicated and kept out on purpose.
 *  - **Private key block.** A committed PEM is a real key wherever it sits; the
 *    cross-tool corpus judged both of these CORRECT (firecrawl's TLS-skip
 *    fixture, axios's `key.pem`) and they must keep firing.
 */
const TYPED_TEST_DOWNGRADEABLE = new Set([
  'AWS access key',
  'GitHub token',
  'Stripe live secret key',
  'Anthropic API key',
  'OpenAI API key',
  'Google API key',
  'Slack token',
])

/**
 * Consecutive characters, ascending or descending by one, before a value stops
 * looking drawn at random. Nine is what `AKIA1234567890ABCDEF` gives (the digit
 * run breaks at `9`→`0`), so the floor sits just below it.
 */
const SYNTHETIC_RUN = 8

/** Longest run of characters each exactly one step from the previous. */
function longestStepRun(chars: string): number {
  let best = chars.length > 0 ? 1 : 0
  let run = 1
  let direction = 0
  for (let i = 1; i < chars.length; i++) {
    const step = chars.charCodeAt(i) - chars.charCodeAt(i - 1)
    if (step === direction && (step === 1 || step === -1)) run++
    else if (step === 1 || step === -1) {
      direction = step
      run = 2
    } else {
      direction = 0
      run = 1
    }
    if (run > best) best = run
  }
  return best
}

/**
 * Whether a credential body was TYPED rather than generated.
 *
 * Real credentials are random over their alphabet; the fixtures that flooded
 * the cross-tool corpus were people walking the keyboard —
 * `AKIA1234567890ABCDEF`, `ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ`,
 * `sk-proj-Ab12_Cd34-Ef56Gh78…`. The letters and the digits are projected out
 * separately and case-folded, because the third example interleaves them: its
 * letters alone spell the alphabet while its digits alone count.
 *
 * Anchored the same way {@link FAKE_LITERAL_VALUE} is, and for the same reason
 * — a predicate that silently downgrades a leak has to be measured, not
 * assumed. A run of eight in a random base62 body needs seven consecutive
 * successes at 1/26 (letters) or 1/10 (digits); the test suite draws 20,000
 * bodies and requires zero hits.
 */
export function hasSyntheticSequence(value: string): boolean {
  const letters = value.replace(/[^A-Za-z]/g, '').toLowerCase()
  if (longestStepRun(letters) >= SYNTHETIC_RUN) return true
  return longestStepRun(value.replace(/\D/g, '')) >= SYNTHETIC_RUN
}

/** Whether a match in a test path may be downgraded to LOW. */
function downgradeableInTests(credentialType: string, matched: string): boolean {
  if (TEST_DOWNGRADEABLE.has(credentialType)) return true
  return TYPED_TEST_DOWNGRADEABLE.has(credentialType) && hasSyntheticSequence(matched)
}

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
          // Announced rather than silent, for the same reason the placeholder
          // skip above is: a secret scanner that quietly drops lines is
          // indistinguishable from one that never read them.
          if (documentsAnExample(line, match, subject)) {
            report(() => ({
              category: 'SECURITY_HYGIENE',
              severity: 'INFO',
              title: `Documented ${name} example ignored in ${file.path.split('/').pop()}`,
              description: `Line ${i + 1} of ${file.path} matches a ${name} pattern inside a code span on a comment line, and the value is provably not a credential — it either spells out its own key or was typed rather than generated. It is NOT reported as a leak. Shown only to confirm the scanner read this line.`,
              filePath: file.path,
              line: i + 1,
              suggestion: 'No action needed. A random value in the same position, or the same value outside a comment, would be reported.',
              impactScore: 5,
              effort: 'low',
              metadata: { credentialType: name, documentedExample: true },
            }))
            break
          }
          // Publishable client identifiers, before any severity is assigned —
          // including the `.env` escalation below, which is what made these
          // CRITICAL. The file being a committed `.env` is not evidence about a
          // value the framework publishes to every visitor anyway.
          if (PUBLISHABLE_CREDENTIAL_TYPES.has(name)) {
            if (isFirebaseWebApiKey(lines, i)) {
              report(() => ({
                category: 'SECURITY_HYGIENE',
                severity: 'INFO',
                title: `Firebase web API key (public by design) in ${file.path.split('/').pop()}`,
                description: `Line ${i + 1} of ${file.path} binds \`apiKey\` to a Google web-format key surrounded by a Firebase web app config (authDomain, projectId, storageBucket, messagingSenderId, appId). That config is compiled into the browser bundle by design and Google documents this key as a public client identifier, not a secret, so it is NOT reported as a leak. A Google API key under any other name, or one whose neighbours are not this config, is still reported.`,
                filePath: file.path,
                line: i + 1,
                suggestion: 'No action needed for the key itself — it is already public in every client that loads this app. What protects the project is Firebase Security Rules, App Check, and an application restriction on the key in the Google Cloud console; confirm those are in place.',
                impactScore: 5,
                effort: 'low',
                metadata: { credentialType: name, publishableClientKey: true, firebaseWebConfig: true },
              }))
              break
            }
            const published = PUBLISHABLE_ENV_BINDING.exec(line)
            if (published) {
              report(() => ({
                category: 'SECURITY_HYGIENE',
                severity: 'LOW',
                title: `Browser-published ${name} under ${published[1]} in ${file.path.split('/').pop()}`,
                description: `Line ${i + 1} of ${file.path} assigns a ${name} to \`${published[1]}\`, whose prefix tells the build tool to inline the value into the client bundle. It is therefore already public to every visitor, so committing it is not the leak — but a browser key is only as safe as its restrictions. Reported for confirmation rather than as a committed credential.`,
                filePath: file.path,
                line: i + 1,
                suggestion: `Confirm this is a client key and restrict it in the Google Cloud console — by referrer or app, and by API. If a SERVER key was pasted under a public-prefixed name it is already exposed to every visitor: rotate it and move it to a variable the build tool does not publish.`,
                impactScore: 20,
                effort: 'low',
                metadata: { credentialType: name, publishableClientKey: true, publicEnvPrefix: published[1] },
              }))
              break
            }
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
            if (value && restatesItsKey(line, match.index ?? 0, value)) continue
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
          const typedFixture = isTestContext && TYPED_TEST_DOWNGRADEABLE.has(name)
          if (!isEnvFile && (messageString || (isTestContext && downgradeableInTests(name, match[0])))) {
            report(() => ({
              category: 'SECURITY_HYGIENE',
              severity: 'LOW',
              title: messageString
                ? `Message text under a credential-shaped key in ${baseName}`
                : `Test fixture resembling a secret: ${name} in ${baseName}`,
              description: messageString
                ? `Line ${i + 1} of ${file.path} assigns a credential-shaped key a value containing spaces, which reads as display text (a validation message, translation, or label) rather than a credential. Reported for awareness only — confirm no real passphrase was pasted here.`
                : typedFixture
                  ? `Line ${i + 1} of ${file.path} contains a value shaped like a ${name}. It sits in test/fixture code AND its body is a typed sequence (runs of consecutive letters or digits) rather than a random credential, so it is most likely a fixture — but confirm no real credential was pasted. A ${name} with a random body in this same file is still reported as a leak.`
                  : `Line ${i + 1} of ${file.path} contains a value shaped like a ${name}. It sits in test/fixture code and does not match a production key format, so it is most likely a fixture — but confirm no real credential was pasted.`,
              filePath: file.path,
              line: i + 1,
              suggestion: messageString
                ? 'No action needed if this is user-facing copy. If a real passphrase was pasted here, rotate it and move it to environment configuration.'
                : 'Use an obviously fake placeholder (e.g. "test-not-a-real-key") so scanners and reviewers can dismiss it at a glance.',
              impactScore: messageString ? 10 : 25,
              effort: 'low',
              metadata: { credentialType: name, testContext: isTestContext, messageString, ...(typedFixture ? { syntheticSequence: true } : {}) },
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
