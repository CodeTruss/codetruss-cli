import type { SastLanguage, SyntaxNode } from './lang'
import { CWE } from './cwe'
import type { Severity } from './types'
import {
  asCall,
  asFunction,
  asMember,
  boolLiteralValue,
  collectAssignments,
  concatOperands,
  dottedName,
  identifierName,
  interpolationExprs,
  isFunctionNode,
  isTaggedTemplate,
  numberLiteralValue,
  stringLiteralValue,
  subscriptBase,
  unwrap,
  walk,
  type NCall,
} from './normalize'
import { readModifyWriteHits } from './rmw'
import { sourceKindOf } from './taint'

/**
 * The curated, high-precision rule pack.
 *
 * Two rule shapes share the CWE/OWASP metadata surface:
 *  - {@link TaintSink}: a dangerous call whose flagged argument MUST be taint-
 *    influenced. This is what makes injection rules precise — a constant or
 *    parameterized argument produces no origins, so no finding.
 *  - {@link PatternRule}: a dangerous API or insecure configuration that is a
 *    finding by its mere presence (weak hash, disabled TLS, deserialization of
 *    an inherently unsafe format). No dataflow to show — hence no flow in the
 *    finding, only the sink site.
 */

export interface RuleMeta {
  id: string
  cweKey: keyof typeof CWE
  severity: Severity
  /** Languages this rule applies to; null = all covered languages. */
  languages: Set<SastLanguage> | null
  title: string
  message: string
  remediation: string
}

export interface TaintSink extends RuleMeta {
  /**
   * If this call is a sink, return the argument indexes whose taint makes it a
   * finding (any one tainted → report). Return null if the call is not this
   * sink. An empty array means "reached at all is dangerous" (rare).
   */
  match(call: NCall, lang: SastLanguage): number[] | null
  /**
   * 'head' = only taint that can steer the START of the argument (a URL's
   * scheme/authority) is dangerous; the engine suppresses taint confined to
   * later path/query segments of a constant-authority string.
   */
  taintPosition?: 'head'
  /**
   * Report a dangerous argument that is exactly one of the enclosing function's
   * PARAMETERS, with no untrusted source behind it.
   *
   * Off for every sink but SQL, and deliberately so. A parameter reaching a
   * sink is normally not a finding — the analysis cannot see the call sites, so
   * `readFile(name)` in a helper says nothing. SQL is the exception because the
   * argument is not data but the *program being executed*: a function whose
   * whole query text comes from its caller has no constraint on what runs, and
   * nothing later in the file can add one. That is what the ten-repository
   * corpus caught us missing on `uptime-kuma/server/monitor-types/postgres.js`.
   *
   * The engine still suppresses it when any same-file call site binds a safe
   * construction (a string literal or a tagged template) to that parameter,
   * because then the file DOES show what runs.
   */
  callerSuppliedArg?: {
    severity: Severity
    /**
     * Positive evidence that this call really is the sink, required because
     * there is no taint flow to supply it. {@link match} may be generous about
     * a method name when a request source has already been traced into it; with
     * only a parameter behind the argument the name is all there is, and
     * `this.query(rightIndex)` in a Fenwick tree is not a database.
     */
    appliesTo(call: NCall, lang: SastLanguage): boolean
    /** Prose for the finding, given the function and parameter names. */
    message(fnName: string, paramName: string): string
    remediation: string
  }
}

export interface PatternHit {
  node: SyntaxNode
  line: number
  detail?: string
}

export interface PatternRule extends RuleMeta {
  /** Skip the rule entirely for files whose path matches (seed/migration/ops
   *  directories where the pattern is expected and harmless). */
  excludePath?: RegExp
  /** Inspect one AST node; return hits (usually 0 or 1). */
  test(node: SyntaxNode, lang: SastLanguage): PatternHit[]
}

const ALL = null

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const lc = (s: string | null | undefined) => (s ?? '').toLowerCase()

/** Receivers that denote a database connection/cursor/query builder. */
const DB_RECEIVER = /(^|[._])(db|conn|connection|client|pool|knex|sequelize|prisma|pg|mysql|sqlite|cursor|session|stmt|statement|sql|repository|dao|orm)/i
/** Method names that always execute SQL. */
/** Receivers that denote Node's child_process module (child_process.exec,
 *  childProcess.exec, cp.exec) rather than a RegExp. */
const CHILD_PROCESS_RECEIVER = /(^|[._])(child_?process|cp|proc|shell)$/i

const SQL_ALWAYS = new Set(['query', 'raw', 'unsafe', 'executequery', 'executeupdate', 'executesql', 'rawquery'])
/** Method names that execute SQL only on a DB-ish receiver. */
const SQL_GATED = new Set(['execute', 'exec', 'executemany'])
/** The DB-API cursor methods among {@link SQL_GATED}: for these the receiver may
 *  also be proven a cursor by its binding, not just by its name. `exec` stays
 *  name-gated — a bare `.exec()` is RegExp.prototype.exec far more often than
 *  it is SQL, and resolving its binding would buy nothing but scan time. */
const CURSOR_METHODS = new Set(['execute', 'executemany'])

/** A `<conn>.cursor()` call — the DB-API idiom that hands back a cursor. */
function isCursorFactoryCall(node: SyntaxNode, lang: SastLanguage): boolean {
  const c = asCall(unwrap(node, lang), lang)
  return !!c && !!c.receiver && lc(c.method) === 'cursor'
}

/**
 * True when this call's receiver is a local BOUND to a DB cursor —
 * `cur = conn.cursor()` or `with conn.cursor() as cur:` — rather than a name
 * that merely reads DB-ish.
 *
 * {@link DB_RECEIVER} is a purely lexical test. It catches `cursor.execute(...)`
 * and the direct chain `conn.cursor().execute(...)` (whose dotted receiver name
 * is `conn.cursor`), but goes blind the moment the cursor is parked in a short
 * local — `cur`, `c`, `crsr` — which is how most psycopg/sqlite3/MySQLdb code is
 * actually written. Resolving the binding restores that canonical two-step form
 * without loosening the lexical gate to generic names, which would cost
 * precision everywhere else.
 */
function receiverBindsToCursor(call: NCall, lang: SastLanguage): boolean {
  if (!call.receiver) return false
  const name = identifierName(call.receiver, lang)
  if (!name) return false
  // Innermost enclosing scope that binds the name wins (program root last).
  let scope: SyntaxNode | null = call.node.parent
  for (let i = 0; i < 60 && scope; i++) {
    const isRoot = scope.parent === null
    if (isFunctionNode(scope, lang) || isRoot) {
      const fn = isFunctionNode(scope, lang) ? asFunction(scope, lang) : null
      const body = isRoot && !fn ? scope : fn?.body
      if (body) {
        const defs = [
          ...collectAssignments(body, lang).filter((a) => a.target === name).map((a) => a.value),
          ...withAliasDefs(body, name, lang),
        ]
        if (defs.length > 0) return defs.some((d) => isCursorFactoryCall(d, lang))
      }
    }
    scope = scope.parent
  }
  return false
}

/** `with <expr> as name:` bindings in a scope — python models them as an
 *  `as_pattern`, which {@link collectAssignments} does not treat as a def. */
function withAliasDefs(body: SyntaxNode, name: string, lang: SastLanguage): SyntaxNode[] {
  const out: SyntaxNode[] = []
  const visit = (node: SyntaxNode) => {
    if (node !== body && isFunctionNode(node, lang)) return // separate scope
    if (node.type === 'as_pattern') {
      const alias = node.childForFieldName('alias')
      const value = node.namedChildren[0]
      const bound = alias ? identifierName(alias.namedChildren[0] ?? alias, lang) : null
      if (value && bound === name) out.push(value)
    }
    for (const c of node.namedChildren) visit(c)
  }
  visit(body)
  return out
}

// NOTE: generic receiver names like `client`/`session` are deliberately NOT here.
// They match Redis/DB/gRPC/GraphQL clients (`client.get(id)`), which are not HTTP
// requests — including them fires SSRF on cache/DB reads (false positives).
const HTTP_CLIENTS = new Set([
  'axios', 'http', 'https', 'requests', 'got', 'superagent', 'fetch',
  'httpclient', 'urllib', 'urllib.request', 'node-fetch', 'undici', 'webclient',
])

/**
 * Receivers that navigate the BROWSER: `location`, `window.location`,
 * `document.location`. Gating on the receiver is what keeps `assign` and
 * `replace` — `Object.assign`, `String.prototype.replace` — from firing.
 */
const NAVIGATION_RECEIVER = /(^|\.)location$/
/** Receivers of a client-side router: Next.js `router`, History-API `history`. */
const ROUTER_RECEIVER = /(^|\.)(router|history)$/

/** A keyword/option argument `name=value` present among a call's args (py/js). */
function findOption(call: NCall, lang: SastLanguage, name: string): SyntaxNode | null {
  const want = name.toLowerCase()
  for (const a of call.args) {
    // python keyword_argument
    if (a.type === 'keyword_argument') {
      const kn = a.childForFieldName('name')?.text
      if (lc(kn) === want) return a.childForFieldName('value')
    }
    // js object option: look one level into object literals for a matching pair
    if (a.type === 'object') {
      for (const pair of a.namedChildren) {
        if (pair.type !== 'pair') continue
        const kn = pair.childForFieldName('key')?.text?.replace(/['"]/g, '')
        if (lc(kn) === want) return pair.childForFieldName('value')
      }
    }
  }
  return null
}

function optionIsTrue(call: NCall, lang: SastLanguage, name: string): boolean {
  const v = findOption(call, lang, name)
  return v ? boolLiteralValue(v, lang) === true : false
}

// ---------------------------------------------------------------------------
// TAINT SINKS
// ---------------------------------------------------------------------------

/** Argument indexes of a call that carry SQL TEXT, before shape filtering. */
function sqlSinkArgs(call: NCall, lang: SastLanguage): number[] | null {
  const m = lc(call.method)
  if (SQL_ALWAYS.has(m)) return [0]
  if (SQL_GATED.has(m)) {
    if (DB_RECEIVER.test(call.receiverName ?? '')) return [0]
    if (CURSOR_METHODS.has(m) && receiverBindsToCursor(call, lang)) return [0]
  }
  // Go database/sql, gated on a DB-ish receiver. Context variants take
  // (ctx, query, ...args) so the SQL string is argument 1, not 0.
  if (DB_RECEIVER.test(call.receiverName ?? '')) {
    if (m === 'queryrow') return [0]
    if (m === 'querycontext' || m === 'queryrowcontext' || m === 'execcontext') return [1]
  }
  // Prisma raw escape hatches. Only the Unsafe variants take a plain SQL
  // string — tagged $queryRaw/$executeRaw templates are parameterized by
  // Prisma and must NOT flag. (asCall strips the leading $, so match both.)
  if (/^\$?(query|execute)rawunsafe$/.test(m)) return [0]
  // C#/Java: new SqlCommand(sql) / new Statement(sql)
  if (call.isConstruct && /sqlcommand|npgsqlcommand|mysqlcommand|oledbcommand/i.test(call.fullName)) return [0]
  return null
}

export const TAINT_SINKS: TaintSink[] = [
  // ---- SQL injection ----
  {
    id: 'sql-injection',
    cweKey: 'SQLI',
    severity: 'CRITICAL',
    languages: ALL,
    title: 'SQL injection',
    message: 'Untrusted input is concatenated into a SQL query and executed. An attacker can alter the query to read or modify arbitrary data.',
    remediation: 'Use parameterized queries / prepared statements and pass user input as bound parameters, never string concatenation.',
    callerSuppliedArg: {
      severity: 'HIGH',
      // `query`/`raw`/`exec` are SQL sinks on any receiver once a request source
      // has been traced into them. With only a parameter behind the argument
      // the receiver is the entire case that this is a database at all, and the
      // ten-repository corpus made the point: `this.query(rightIndex)` inside
      // `FenwickTree.queryRange` is a prefix-sum lookup, reported twice before
      // this gate and correctly silent after it.
      appliesTo: (call) => DB_RECEIVER.test(call.receiverName ?? ''),
      message: (fnName, paramName) =>
        `${fnName}() executes the SQL text it receives in its \`${paramName}\` parameter. The query is not built in this file, so nothing here constrains what a caller can run, and no call site in this file binds a constant or a parameterized template to it. Whether this is injectable is decided entirely by callers the analysis cannot see.`,
      remediation:
        'Keep the query text a constant inside this function and accept only bound parameters from callers. If callers genuinely must choose the statement, validate their input against an allow-list of known queries rather than executing it verbatim.',
    },
    match(call, lang) {
      const idxs = sqlSinkArgs(call, lang)
      // A tagged template hands its interpolations to the tag as bound values
      // instead of splicing them into the string, so it is the parameterized
      // construction, not concatenation — the exemption Prisma's `$queryRaw`
      // already had inside `sqlSinkArgs`, expressed as the SHAPE so drizzle's
      // `sql`, slonik, postgres.js and the next library to adopt it are too. The
      // escape hatches (`sql.raw`, `$queryRawUnsafe`) are ordinary calls, not
      // tagged templates, so they still match — including nested inside one.
      return idxs && idxs.filter((i) => !call.args[i] || !isTaggedTemplate(call.args[i], lang))
    },
  },

  // ---- Command injection ----
  {
    id: 'command-injection',
    cweKey: 'CMDI',
    severity: 'CRITICAL',
    languages: ALL,
    title: 'OS command injection',
    message: 'Untrusted input flows into a shell command. An attacker can inject additional commands and run arbitrary code on the host.',
    remediation: 'Avoid the shell: pass an argument array to execFile/spawn/subprocess without shell=True, and validate against an allow-list.',
    match(call, lang) {
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      // Node child_process shell APIs. In JS a bare `.exec()` on an arbitrary
      // receiver is overwhelmingly RegExp.prototype.exec (`/re/.exec(s)`,
      // minified `S.exec(a)`), so require a child_process-shaped receiver or a
      // destructured import. Other languages have no regex `.exec` idiom and
      // keep the broader gate.
      if (m === 'exec' || m === 'execsync') {
        if (lang === 'javascript' || lang === 'typescript' || lang === 'tsx') {
          // Require positive evidence of child_process. An `exec` reached
          // through ANY member access whose object is not child_process-shaped
          // (`/re/.exec(s)`, `pattern.exec(s)`, minified `S.exec(a)`) is
          // RegExp.prototype.exec. Only a bare callee — the destructured
          // `const { exec } = require('child_process')` — flags without a name.
          const memberCallee = call.callee ? asMember(call.callee, lang) : null
          if (!memberCallee || CHILD_PROCESS_RECEIVER.test(recv)) return [0]
          // Decided: a JS `.exec` reached through a non-child_process object is
          // RegExp.prototype.exec. Return rather than fall through — the PHP
          // branch below keys off a null receiverName, which a regex LITERAL
          // receiver also has.
          return null
        }
        if (!DB_RECEIVER.test(recv)) return [0]
      }
      if ((m === 'spawn' || m === 'spawnsync' || m === 'execfile') && optionIsTrue(call, lang, 'shell')) return [0]
      // Python
      if (recv === 'os' && (m === 'system' || m === 'popen')) return [0]
      if (/subprocess/.test(recv) && (m === 'call' || m === 'run' || m === 'popen' || m === 'check_output' || m === 'check_call')) {
        return optionIsTrue(call, lang, 'shell') ? [0] : null
      }
      // Java Runtime.exec / new ProcessBuilder
      if (m === 'exec' && /runtime/.test(recv)) return [0]
      if (call.isConstruct && /processbuilder/i.test(call.fullName)) return call.args.map((_, i) => i)
      // C# Process.Start
      if (m === 'start' && /process/.test(recv)) return [0]
      // Go exec.Command
      if (m === 'command' && recv === 'exec') return call.args.map((_, i) => i)
      // PHP
      if (['system', 'exec', 'shell_exec', 'passthru', 'proc_open'].includes(m) && !call.receiverName) return [0]
      return null
    },
  },

  // ---- Path traversal ----
  {
    id: 'path-traversal',
    cweKey: 'PATH',
    severity: 'HIGH',
    languages: ALL,
    title: 'Path traversal',
    message: 'Untrusted input is used as a filesystem path without normalization, allowing access to files outside the intended directory (e.g. via "../").',
    remediation: 'Normalize and confine the path (path.basename / realpath) and verify it stays within an allowed base directory before opening.',
    match(call) {
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      const FS_METHODS = new Set([
        'readfile', 'readfilesync', 'writefile', 'writefilesync', 'appendfile', 'createreadstream',
        'createwritestream', 'open', 'opensync', 'unlink', 'readdir', 'readalltext', 'readallbytes',
        'openread', 'openwrite', 'readalllines',
      ])
      if (FS_METHODS.has(m) && !/^(process|require)$/.test(recv)) return [0]
      if (call.isConstruct && /(^|\.)file$|filestream|fileinfo|streamreader/i.test(call.fullName)) return [0]
      return null
    },
  },

  // ---- SSRF ----
  {
    id: 'ssrf',
    cweKey: 'SSRF',
    severity: 'HIGH',
    languages: ALL,
    title: 'Server-side request forgery (SSRF)',
    message: 'A user-controlled URL is passed to an HTTP client, letting an attacker make the server issue requests to internal or arbitrary hosts.',
    remediation: 'Validate the URL against a strict allow-list of hosts/schemes and resolve/deny internal addresses before making the request.',
    // SSRF requires control of the request TARGET — taint in a path segment of
    // a constant-authority URL cannot redirect the request to another host.
    taintPosition: 'head',
    match(call) {
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      if (m === 'fetch' && !recv) return [0]
      if (m === 'urlopen') return [0]
      if ((m === 'get' || m === 'post' || m === 'request' || m === 'put' || m === 'delete') && HTTP_CLIENTS.has(recv)) return [0]
      if (m === 'openconnection') return [0]
      return null
    },
  },

  // ---- Code injection (eval) & reflection ----
  {
    id: 'code-injection',
    cweKey: 'CODEI',
    severity: 'CRITICAL',
    languages: ALL,
    title: 'Code injection via eval',
    message: 'Untrusted input is passed to a dynamic code-evaluation / reflection primitive, allowing arbitrary code execution.',
    remediation: 'Never evaluate untrusted input. Replace eval/exec/Function with an explicit parser or a safe lookup table.',
    match(call) {
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      if (!recv && ['eval', 'exec', 'compile', 'execscript', 'assert', 'create_function'].includes(m)) return [0]
      if (call.isConstruct && /^function$/i.test(call.fullName)) return [0] // new Function(str)
      if (m === 'forname' && /class/.test(recv)) return [0] // Java reflection
      if (['instance_eval', 'class_eval', 'module_eval'].includes(m)) return [0]
      return null
    },
  },

  // ---- Open redirect ----
  {
    id: 'open-redirect',
    cweKey: 'OPENREDIR',
    severity: 'MEDIUM',
    languages: ALL,
    title: 'Open redirect',
    message: 'A user-controlled value is used as a redirect target, enabling phishing by redirecting victims to attacker-chosen sites.',
    remediation: 'Redirect only to a fixed set of allowed paths, or validate the target against an allow-list of hosts.',
    // A redirect is attacker-steerable only when taint can reach the scheme or
    // authority. Taint confined to a path segment of an origin-relative target
    // (`/users/<id>`) cannot send the victim off-origin.
    taintPosition: 'head',
    match(call) {
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      if (m === 'redirect' || m === 'sendredirect') return [0]
      // Browser navigation — `location.assign(url)`, `window.location.replace(url)`.
      // Receiver-gated: a bare `replace` is String.prototype.replace.
      if ((m === 'assign' || m === 'replace') && NAVIGATION_RECEIVER.test(recv)) return [0]
      // Client router — `router.push(url)`, `history.replace(url)`. Same gate:
      // `push` unqualified is Array.prototype.push on nearly every line it appears.
      if ((m === 'push' || m === 'replace') && ROUTER_RECEIVER.test(recv)) return [0]
      return null
    },
  },

  // ---- ReDoS (user-controlled regex) ----
  {
    id: 'redos',
    cweKey: 'REDOS',
    severity: 'MEDIUM',
    languages: ALL,
    title: 'User-controlled regular expression (ReDoS)',
    message: 'A regular expression is built from untrusted input; a crafted pattern can cause catastrophic backtracking and hang the process.',
    remediation: 'Do not build regexes from user input. If unavoidable, use a linear-time regex engine (RE2) or strictly validate the pattern.',
    match(call) {
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      if (call.isConstruct && /^regexp$/i.test(call.fullName)) return [0]
      if (m === 'compile' && /^re$/.test(recv)) return [0] // python re.compile
      return null
    },
  },

  // ---- PHP unserialize (insecure deserialization, tainted) ----
  {
    id: 'php-object-injection',
    cweKey: 'DESER',
    severity: 'HIGH',
    languages: new Set<SastLanguage>(['php']),
    title: 'PHP object injection via unserialize()',
    message: 'unserialize() on untrusted input can instantiate arbitrary objects and trigger magic methods, leading to code execution.',
    remediation: 'Use json_decode() for untrusted data, or unserialize() with a strict allowed_classes list.',
    match(call) {
      if (lc(call.method) === 'unserialize' && !call.receiverName) return [0]
      return null
    },
  },

  // ---- Unbounded allocation from an untrusted length (CardShopCoop Msg.cs) ----
  {
    id: 'unbounded-read',
    cweKey: 'ALLOC',
    severity: 'MEDIUM',
    languages: new Set<SastLanguage>(['csharp', 'java']),
    title: 'Unbounded allocation from untrusted length',
    message: 'A length read off an untrusted stream is used to allocate/read a buffer with no bound. A hostile peer can send a huge length to exhaust memory (DoS), the core of untrusted binary-protocol deserialization bugs.',
    remediation: 'Validate the declared length against a sane maximum before allocating or calling ReadBytes; reject oversized frames.',
    match(call) {
      const m = lc(call.method)
      // Include the idiomatic `br`/`rdr` reader abbreviations, not just receivers
      // literally named reader/stream (CardShopCoop `var br = Msg.Reader(...)`).
      if (m === 'readbytes' && /reader|stream|buffer|^(br|rdr)$/.test(lc(call.receiverName))) return [0]
      return null
    },
  },

  // ---- Decompression of untrusted compressed data (zip/gzip bomb) ----
  {
    id: 'decompression-bomb',
    cweKey: 'DECOMP',
    severity: 'MEDIUM',
    languages: new Set<SastLanguage>(['csharp', 'java', 'javascript', 'typescript', 'tsx']),
    title: 'Decompression of untrusted compressed data',
    message: 'Attacker-influenced compressed data is decompressed with no size cap. A crafted highly-compressible payload (zip/gzip bomb) expands to exhaust memory or disk (DoS).',
    remediation: 'Cap the decompressed size (bounded copy / max output length) and reject inputs whose expansion ratio or absolute size exceeds a sane limit before decompressing.',
    match(call) {
      const m = lc(call.method)
      if (['gunzip', 'ungzip', 'inflate', 'decompress', 'unzip', 'inflatesync', 'gunzipsync'].includes(m)) return [0]
      // C#/Java decompression streams: new GZipStream(src, Decompress) / new GZIPInputStream(src)
      if (call.isConstruct && /gzipstream|deflatestream|brotlistream|gzipinputstream|inflaterinputstream|zipinputstream/i.test(call.fullName)) {
        return [0]
      }
      return null
    },
  },
]

// ---------------------------------------------------------------------------
// PATTERN RULES
// ---------------------------------------------------------------------------

/** Extract a `name = value` / `name: value` / `name=value` binding from a node. */
export function asNamedValue(
  node: SyntaxNode,
  lang: SastLanguage,
): { name: string; value: SyntaxNode; node: SyntaxNode } | null {
  const t = node.type
  const clean = (s: string | undefined | null) => lc(s).replace(/^[$'"]+|['"]+$/g, '')
  const f = (name: string) => node.childForFieldName(name)

  if (t === 'pair') {
    const key = f('key')
    const value = f('value')
    if (key && value) return { name: clean(key.text), value, node }
  }
  if (t === 'keyword_argument') {
    const value = f('value')
    if (value) return { name: clean(f('name')?.text), value, node }
  }
  if (t === 'keyed_element') {
    // go composite literal field
    const key = f('key') ?? node.namedChildren[0]
    const value = f('value') ?? node.namedChildren[node.namedChildren.length - 1]
    if (key && value && key !== value) return { name: clean(key.text), value, node }
  }
  if (t === 'variable_declarator') {
    const nameNode = f('name')
    const value = f('value')
    if (nameNode && value) return { name: clean(nameNode.text), value, node }
  }
  if (t === 'jsx_attribute') {
    // `<Link href={to}>`. Neither grammar names the value with a field, and the
    // `=` between them is anonymous, so the name is the first named child and
    // the value the last; a valueless attribute (`disabled`) has only one.
    const nameNode = node.namedChildren[0]
    const valueNode = node.namedChildren[node.namedChildren.length - 1]
    if (nameNode && valueNode && nameNode !== valueNode) {
      // `{to}` is an expression container; the expression inside it is the value.
      const value = valueNode.type === 'jsx_expression' ? valueNode.namedChildren[0] : valueNode
      if (value) return { name: clean(nameNode.text), value, node }
    }
  }
  if (t === 'assignment_expression' || t === 'assignment') {
    const left = f('left')
    const right = f('right')
    if (left && right) {
      const name = identifierName(left, lang) ?? dottedName(left, lang)
      const last = name ? name.slice(name.lastIndexOf('.') + 1) : null
      if (last) return { name: clean(last), value: right, node }
    }
  }
  return null
}

/** Climb parents looking for a binding whose name matches `re`. */
function nameContext(node: SyntaxNode, lang: SastLanguage, re: RegExp): string | null {
  let cur: SyntaxNode | null = node
  for (let i = 0; i < 5 && cur; i++) {
    const nv = asNamedValue(cur, lang)
    if (nv && re.test(nv.name)) return nv.name
    cur = cur.parent
  }
  return null
}

/** Climb parents looking for an enclosing call whose method matches `re`. */
function callContext(node: SyntaxNode, lang: SastLanguage, re: RegExp): boolean {
  let cur: SyntaxNode | null = node
  for (let i = 0; i < 6 && cur; i++) {
    const call = asCall(cur, lang)
    if (call && re.test(call.method)) return true
    cur = cur.parent
  }
  return false
}

// ---- weak-hash purpose context --------------------------------------------
/** Non-security purposes for an MD5/SHA-1 hash: content-addressing, dedup, ETag. */
const NONSEC_HASH_PURPOSE = /fingerprint|dedup|duplicat|etag|cache|checksum|identity|shard|bucket|content.?hash|node.?id|filename/i
/** A variable literally named for a generic content hash (not a security digest). */
const GENERIC_HASH_NAME = /^(sha|sha1|hash|digest|etag|checksum|fingerprint|cachekey|contenthash|nodeid)$/i
/** Words that mark a hash as security-relevant — never suppress these. */
const SECURITY_HASH_WORD = /password|passwd|secret|token|sign|hmac|cert|credential|\bauth\b|private|integrity/i

/**
 * True when an MD5/SHA-1 hash is used for a non-security purpose (fingerprinting,
 * dedup, ETag, content identity), inferred from the enclosing variable/function
 * names. A single overriding security word (password, signature, hmac, …) keeps
 * the finding. This kills the clean-repo weak-hash false positives without
 * requiring a positive security signal on the true-positive cases.
 */
function isNonSecurityHash(node: SyntaxNode, lang: SastLanguage): boolean {
  let cur: SyntaxNode | null = node
  let purpose = false
  for (let i = 0; i < 12 && cur; i++) {
    const nv = asNamedValue(cur, lang)
    if (nv) {
      if (SECURITY_HASH_WORD.test(nv.name)) return false
      if (NONSEC_HASH_PURPOSE.test(nv.name) || GENERIC_HASH_NAME.test(nv.name)) purpose = true
    }
    const fn = asFunction(cur, lang)
    if (fn) {
      if (SECURITY_HASH_WORD.test(fn.name)) return false
      if (NONSEC_HASH_PURPOSE.test(fn.name)) purpose = true
    }
    cur = cur.parent
  }
  return purpose
}

const SECRET_NAME = /(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?key|bearer[_-]?token|encryption[_-]?key)/i
const CRED_PLACEHOLDER = /(example|placeholder|your[_-]?|xxx|changeme|dummy|test|fake|sample|<[^>]+>|\$\{|process\.env|os\.getenv|getenv)/i
/**
 * Values that are a NAME/label, not a secret: an HTTP header name (`x-api-key`),
 * an OAuth field/param name (`client_secret`), or a bare key prefix constant
 * (`ct_live_`). Real credentials carry entropy (digits / mixed case); these are
 * lowercase dictionary tokens or `x-…` header names. Excluding them kills the
 * `API_KEY_PREFIX = 'ct_live_'` / `authToken = 'x-auth-token'` false positives.
 */
// Kebab/dotted segments are label shapes too (`sb-access-token`,
// `next-auth.session-token`). Digits stay out of those segments so a real key
// like `sk_live_abc1234567890abcdef` is still reported.
const CRED_LABEL_VALUE = /^(x-[a-z0-9-]+|[a-z][a-z_]*|[a-z]+([-._][a-z]+)*)$/i

/**
 * Documentation/API endpoint constants often have credential-shaped names
 * (`*_ACCESS_TOKENS`, `*_PRIVATE_KEYS`) but their values are ordinary public
 * URLs. Suppress only URLs with no embedded credentials, query, fragment, or
 * token-looking path segment. Signed URLs, webhook secrets, and other
 * high-entropy URL credentials therefore remain findings.
 */
/**
 * A relative path is a destination, not a credential: dashboards are full of
 * route and asset maps keyed by an entity enum (`API_KEY: '/settings/api-keys'`).
 * Requiring a path separator keeps a bare token like `sk_live_…` reportable.
 */
const RELATIVE_PATH_VALUE = /^\.{0,2}\/[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*\/?$/

function isNonCredentialUrlLiteral(value: string): boolean {
  if (RELATIVE_PATH_VALUE.test(value)) return true
  if (!/^https?:\/\//i.test(value)) return false
  try {
    const url = new URL(value)
    if (url.username || url.password || url.search || url.hash) return false
    const tokenLikePath = url.pathname
      .split('/')
      .filter(Boolean)
      .some((segment) => {
        let decoded: string
        try {
          decoded = decodeURIComponent(segment)
        } catch {
          return true
        }
        if (decoded.length < 20) return false
        const jwtParts = decoded.split('.')
        if (
          decoded.length >= 40 &&
          jwtParts.length === 3 &&
          jwtParts.every((part) => part.length >= 8 && /^[A-Za-z0-9_-]+$/.test(part))
        ) {
          return true
        }
        if (!/^[A-Za-z0-9_=-]+$/.test(decoded)) return false
        return (
          (/[A-Za-z]/.test(decoded) && /\d/.test(decoded)) ||
          (/[a-z]/.test(decoded) && /[A-Z]/.test(decoded)) ||
          /^[A-Fa-f0-9]{20,}$/.test(decoded) ||
          /^[A-Z0-9_=-]{20,}$/.test(decoded)
        )
      })
    return !tokenLikePath
  } catch {
    return false
  }
}
// Only names that unambiguously denote a SECRET. Bare `key`/`session`/`iv`/`seed`
// are excluded: they overwhelmingly name non-secret values (React list keys, map
// keys, cache keys, session objects) and `iv`/`seed` even match as substrings of
// unrelated words (`private`, `seeded`). Compound secret names are kept.
const RNG_NAME = /(token|secret|nonce|salt|otp|password|passwd|apikey|privatekey|secretkey|encryptionkey|signingkey|sessionid|accesskey|credential)/i

// ---- timing-unsafe secret comparison ---------------------------------------
const EQ_OPS = new Set(['==', '===', '!=', '!=='])
/**
 * Names that unambiguously denote a secret VALUE being verified. Bare `token`
 * is excluded: pagination/cancellation/CSRF-in-state tokens are compared with
 * `===` legitimately all the time — compound *_token names are kept.
 */
const SECRET_COMPARE_NAME =
  /(secret|password|passwd|signature|hmac|api[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token|session[_-]?token)/i

/** Identifier continues past the secret word with an attribute segment
 *  (APIKeyAuthorityAdmin, apiKeyStatus): it names a property or category OF
 *  the secret, not the secret bytes. Plain continuations like SecretKey or
 *  passwordHash still denote the value itself and stay eligible. */
const SECRET_ATTRIBUTE_REST =
  /(authority|type|kind|status|state|name|prefix|preview|scope|mode|source|version|count|limit|role|level|owner|label|header|error|policy|expir)/i

/** Leaf property names that dereference the actual secret bytes when only the
 *  RECEIVER is secret-named (secret.value, apiKey.hash). */
const SECRET_VALUE_LEAF = /^(value|val|text|str|string|raw|data|bytes|content|plaintext|hash|digest)$/i

/** The password-confirmation idiom: `password != confirm`,
 *  `form.password !== form.confirmPassword`. Both sides are values the same
 *  user just supplied, so timing reveals nothing they do not already know. */
const CONFIRMATION_NAME = /(confirm|retype|repeat|again|re[_-]?enter)/i

const PASSWORD_NAME = /pass(word|wd|phrase)?/i
/** Yup's sibling-field accessor (`context.parent.password`). Comparing a field
 *  to a sibling of the SAME form is client-side match validation, not secret
 *  verification — both values were typed by the same person. */
const FORM_SIBLING_FIELD = /(^|\.)parent\.[a-z_$]/i
/** Password-change UX: `currentPassword === newPassword` compares two values
 *  from the same user's form, not a stored secret against input. */
const SAME_USER_PASSWORD_PREFIX = /(^|[._-])(new|old|current|previous|prev|proposed)[_-]?pass/i

/** A secret-named value referenced by this comparison operand (directly, or
 *  inside a template/concat like `Bearer ${secret}`). `secret.length`-style
 *  size accesses compare a NUMBER, not the secret bytes — never a hit. */
function secretCompareSide(node: SyntaxNode, lang: SastLanguage, depth = 0): string | null {
  if (depth > 4) return null
  const n = unwrap(node, lang)
  // A call RESULT is a transform (errorSignature(a) === errorSignature(b),
  // hash(x) === hash(y)) — its name describes a function, not a stored secret
  // being verified byte-by-byte.
  if (asCall(n, lang)) return null
  const name = dottedName(n, lang) ?? identifierName(n, lang)
  if (name) {
    const last = name.slice(name.lastIndexOf('.') + 1)
    if (/^(length|size|count)$/i.test(last)) return null
    // *Id / *_id names reference an identifier of the secret, not its bytes —
    // `row.apiKeyId === req.query.apiKeyId` is an identity check.
    if (/id$/i.test(last)) return null
    // The compared VALUE is the final segment: `apiKey.Authority` compares an
    // enum on a secret-named receiver, not the key itself.
    const match = SECRET_COMPARE_NAME.exec(last)
    if (match) {
      const rest = last.slice(match.index + match[0].length)
      return SECRET_ATTRIBUTE_REST.test(rest) ? null : last
    }
    if (SECRET_COMPARE_NAME.test(name) && SECRET_VALUE_LEAF.test(last)) return last
  }
  const parts = interpolationExprs(n, lang) ?? concatOperands(n, lang)
  if (parts) {
    for (const p of parts) {
      const hit = secretCompareSide(p, lang, depth + 1)
      if (hit) return hit
    }
  }
  return null
}

/** Presence/shape checks — comparing a secret to null/undefined/a literal/typeof
 *  is not a byte-by-byte verification, so timing leaks nothing useful. */
function isTrivialCompareOperand(node: SyntaxNode, lang: SastLanguage): boolean {
  const n = unwrap(node, lang)
  if (stringLiteralValue(n, lang) !== null) return true
  if (numberLiteralValue(n, lang) !== null) return true
  if (boolLiteralValue(n, lang) !== null) return true
  if (/^(null|undefined|none|nil)$/i.test(n.text)) return true
  if (/^typeof\b/.test(n.text)) return true
  return false
}

/**
 * Sinks reached by ASSIGNING to a named binding rather than by calling a
 * function — `dangerouslySetInnerHTML={{__html: x}}` is a JSX pair and
 * `el.innerHTML = x` an assignment, so neither is visible to a `match(call)`
 * rule no matter how it is written.
 */
export interface TaintAssignSink extends RuleMeta {
  /** True when this binding writes to the dangerous surface. */
  matchName(name: string): boolean
  /** Sink-local safety: the assigned expression is already safe by construction. */
  safeValue?(value: SyntaxNode, lang: SastLanguage): boolean
  /**
   * Binding SHAPES this sink may be written as, by AST node type. Omitted means
   * every shape `asNamedValue` understands — which for a name as ordinary as
   * `href` would include `const href = …`, a local variable that navigates
   * nothing. A sink whose name is common English restricts itself here.
   */
  sites?: ReadonlySet<string>
  /** See {@link TaintSink.taintPosition}. */
  taintPosition?: 'head'
  /** What the value reaches, named in the finding's prose and metadata. */
  surface: string
}

/**
 * Binding shapes that navigate: a JSX attribute (`<Link href={to}>`, `<form
 * action={to}>`) and an assignment (`location.href = to`). Deliberately not
 * `variable_declarator` or `pair`: naming a local `href` is not navigating, and
 * every route table in a React codebase is objects with `href` keys.
 */
const NAVIGATION_BINDING_SITES: ReadonlySet<string> = new Set([
  'jsx_attribute',
  'assignment_expression',
  'assignment',
])

/**
 * True unless the untrusted value IS the navigation target.
 *
 * The shapes this sink exists for are `href={returnTo}` and
 * `href={searchParams.next}` — the target is the untrusted value, or a field of
 * the request itself. Anything else is a target the untrusted value merely
 * helped BUILD, and in a React codebase that is dominated by one pattern:
 * `href={post.cta?.href ?? '/register'}`, where `post` came back from
 * `getPost(slug)` and the only taint is the route segment used as the lookup
 * key. Reading the key's taint as the record's taint turns every call-to-action
 * in a `[slug]` page into an open redirect — measured, that shape plus a JSX
 * `action` prop holding a component was five false positives in this repository
 * alone, against the one real defect the sink was added to catch.
 *
 * So this sink ships at the precision it can prove. The cost is real and
 * bounded: a target assembled by concatenation or chosen by a ternary is not
 * reported here. Widening is a later change made against measurements.
 */
function navigationTargetIsIndirect(value: SyntaxNode, lang: SastLanguage): boolean {
  const n = unwrap(value, lang)
  if (sourceKindOf(n, lang)) return false
  if (identifierName(n, lang)) return false
  // Walk a member/subscript chain to its root: `searchParams.next`, `req.query.to`.
  let root: SyntaxNode = n
  for (let depth = 0; depth < 12; depth++) {
    const inner = asMember(root, lang)?.object ?? subscriptBase(root)
    if (!inner) break
    root = unwrap(inner, lang)
    if (sourceKindOf(root, lang)) return false
  }
  return true
}

/**
 * `JSON.stringify(x).replace(/</g, '<')` — the standard escaped JSON-LD
 * idiom. The `<` that would open a tag is escaped, so the serialized value
 * cannot break out of the script element.
 */
function isEscapedJsonLd(value: SyntaxNode, lang: SastLanguage): boolean {
  let node = unwrap(value, lang)
  let call = asCall(node, lang)
  // Unwrap a trailing `.replace(...)` chain to reach the serializer.
  while (call && lc(call.method) === 'replace' && call.receiver) {
    if (!/u003c|&lt;/i.test(call.args.map((a) => a.text).join(''))) return false
    node = unwrap(call.receiver, lang)
    call = asCall(node, lang)
  }
  return Boolean(call && /^json\.stringify$/i.test(call.fullName))
}

export const TAINT_ASSIGN_SINKS: TaintAssignSink[] = [
  {
    id: 'xss',
    cweKey: 'XSS',
    severity: 'HIGH',
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Cross-site scripting (XSS)',
    message: 'Untrusted input is written to a raw-HTML surface. A crafted value can inject script that runs with the victim\'s session.',
    remediation: 'Render the value as text instead of HTML, or sanitize it (DOMPurify) before assigning. For JSON embedded in a script tag, serialize with JSON.stringify and escape "<".',
    matchName: (name) => name === '__html' || name === 'innerhtml' || name === 'outerhtml',
    safeValue: isEscapedJsonLd,
    surface: 'a raw-HTML binding',
  },
  {
    // Same rule class as the call-shaped `open-redirect` sink above, and the
    // same id, because it is the same defect: a user-controlled navigation
    // target. Most redirects in a React codebase are never a redirect CALL —
    // they are `<Link href={returnTo}>`, `<form action={next}>` or
    // `location.href = next`, none of which a `match(call)` rule can see.
    id: 'open-redirect',
    cweKey: 'OPENREDIR',
    severity: 'MEDIUM',
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Open redirect',
    message: 'A user-controlled value is used as a navigation target, enabling phishing by sending victims to attacker-chosen sites.',
    remediation: 'Navigate only to a fixed set of allowed paths, or validate the target against an allow-list of hosts.',
    matchName: (name) => name === 'href' || name === 'action',
    sites: NAVIGATION_BINDING_SITES,
    safeValue: navigationTargetIsIndirect,
    // Taint confined to a path segment of an origin-relative target
    // (`/repo/${id}`) cannot send the victim off-origin — which is what keeps
    // this off the interpolated hrefs that make up most of a React app.
    taintPosition: 'head',
    surface: 'a navigation target',
  },
]

/** Build-tool prefixes that inline an env var into the CLIENT bundle. */
const CLIENT_ENV_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_)/
/**
 * Server-only credential names, deliberately NARROW. Reusing the general
 * SECRET_NAME regex here would fire on `NEXT_PUBLIC_GOOGLE_MAPS_API_KEY`,
 * `NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` —
 * all of which are DESIGNED to reach the browser. Only names that have no
 * legitimate client-side use belong here.
 */
const SERVER_ONLY_ENV_NAME =
  /(SERVICE_ROLE|SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|WEBHOOK_SECRET|SESSION_SECRET|JWT_SECRET|NEXTAUTH_SECRET|ENCRYPTION_KEY|DATABASE_URL|CONNECTION_STRING|_PASSWORD|STRIPE_SECRET|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET)/

// ---- un-awaited database write ---------------------------------------------
/**
 * Receiver ROOT segments for the floating-write rule. Deliberately NOT
 * DB_RECEIVER: its client/session/pool alternates are far too generic for a
 * rule keyed on verbs as common as delete/update/create.
 */
const FLOATING_DB_ROOTS = new Set(['db', 'prisma', 'tx', 'trx', 'database'])
const ORM_WRITE_METHODS = new Set([
  'create', 'createmany', 'createmanyandreturn', 'update', 'updatemany', 'upsert',
  'delete', 'deletemany', 'insertone', 'insertmany', 'updateone', 'replaceone',
  'deleteone', 'bulkwrite', 'findoneandupdate', 'findoneanddelete', 'findoneandreplace',
])
/** Verbs that also exist on Map/Set/cookies — these need the object-literal
 *  argument guard (Prisma/Mongo delete filters are always object literals,
 *  `sessions.delete(key)` takes a bare key). */
const DELETEISH_METHODS = new Set(['delete', 'deleteone', 'deletemany', 'findoneanddelete'])
const CONVEX_WRITE_METHODS = new Set(['insert', 'patch', 'replace', 'delete'])
/** A .then/.catch/.finally terminal means the promise IS handled. */
const PROMISE_TERMINALS = new Set(['then', 'catch', 'finally'])
/** Raw SQL driver entry points (pg, mysql2 promise API, generic pools). */
const RAW_QUERY_METHODS = new Set(['query', 'execute'])
/** First keyword of a statement that CHANGES data. */
const SQL_WRITE_STATEMENT = /^\s*(insert|update|delete|upsert|merge|replace)\b/i

/**
 * True when the argument is a SQL string literal (plain or templated) whose
 * first keyword writes. Only the constant HEAD is inspected, so an interpolated
 * query still classifies without evaluating it.
 */
function isSqlWriteArgument(node: SyntaxNode | undefined, lang: SastLanguage): boolean {
  if (!node) return false
  const n = unwrap(node, lang)
  if (n.type !== 'string' && n.type !== 'template_string') return false
  const literal = stringLiteralValue(n, lang)
  return SQL_WRITE_STATEMENT.test(literal ?? n.text.replace(/^[`'"]/, ''))
}

/** Strip AT MOST ONE leading context segment (NestJS `this.prisma.…`, GraphQL
 *  `ctx.prisma.…`). */
const stripContextSegment = (s: string) => s.replace(/^(this|self|ctx|context)\./, '')

/**
 * True when no level of the receiver chain is itself a call. A call inside the
 * chain means a factory/lookup idiom — IndexedDB `tx.objectStore('s').delete(k)`,
 * raw Mongo `db.collection('c').insertOne(…)` — which must not fire.
 */
function receiverChainCallFree(receiver: SyntaxNode | null, lang: SastLanguage): boolean {
  let cur = receiver
  for (let i = 0; i < 12 && cur; i++) {
    const n = unwrap(cur, lang)
    if (asCall(n, lang)) return false
    const m = asMember(n, lang)
    if (!m) return true
    cur = m.object
  }
  return true
}

// ---- swallowed error --------------------------------------------------------
/** Best-effort cleanup calls whose failure is legitimately ignorable. */
const CLEANUP_METHODS = new Set([
  'unlink', 'unlinksync', 'rm', 'rmsync', 'rmdir', 'rmdirsync', 'rimraf', 'remove', 'rmtree',
  'close', 'closesync', 'destroy', 'abort', 'disconnect', 'end', 'kill', 'terminate',
  'dispose', 'release', 'releaselock', 'stop', 'unsubscribe', 'removelistener', 'removealllisteners',
])
/** Receivers whose failures are cosmetic (copy buttons, storage feature checks). */
const CLEANUP_RECEIVER = /(^|\.)clipboard$|^(localstorage|sessionstorage)$/
const BROAD_EXCEPT_TYPES = new Set(['Exception', 'BaseException'])

/** First call in a try body (descending through expression statements and
 *  assignments) — the best-effort-cleanup signal for swallowed-error. */
function firstTryBodyCall(tryNode: SyntaxNode, lang: SastLanguage): NCall | null {
  const body = tryNode.childForFieldName('body')
  const first = body?.namedChildren.find((c) => c.type !== 'comment')
  if (!first) return null
  let expr: SyntaxNode = first
  if (expr.type === 'expression_statement') expr = expr.namedChildren[0] ?? expr
  if (expr.type === 'assignment_expression' || expr.type === 'assignment') {
    expr = expr.childForFieldName('right') ?? expr
  }
  return asCall(unwrap(expr, lang), lang)
}

/** Documented intent adjacent to the try: a comment directly above it, or a
 *  trailing comment on the catch/except clause's closing line. */
function tryHasAdjacentComment(tryNode: SyntaxNode, clauseEndRow: number): boolean {
  const prev = tryNode.previousNamedSibling
  if (prev?.type === 'comment' && prev.endPosition.row >= tryNode.startPosition.row - 1) return true
  let sib = tryNode.nextNamedSibling
  for (let i = 0; i < 3 && sib; i++) {
    if (sib.type === 'comment' && sib.startPosition.row === clauseEndRow) return true
    if (sib.startPosition.row > clauseEndRow) break
    sib = sib.nextNamedSibling
  }
  return false
}

/** try { await unlink(tmp) } catch {} — temp-file/socket cleanup on an error
 *  path, and clipboard/storage best-effort writes. Deliberately ignorable. */
function isBestEffortCleanup(tryNode: SyntaxNode, lang: SastLanguage): boolean {
  const call = firstTryBodyCall(tryNode, lang)
  if (!call) return false
  if (CLEANUP_METHODS.has(lc(call.method))) return true
  return CLEANUP_RECEIVER.test(lc(call.receiverName ?? ''))
}

/** Bare `except:` / Exception / BaseException. A SPECIFIC exception type is a
 *  deliberate-suppression signal and never fires. */
function isBroadExceptType(typeNode: SyntaxNode): boolean {
  if (typeNode.type === 'identifier') return BROAD_EXCEPT_TYPES.has(typeNode.text)
  if (typeNode.type === 'as_pattern') {
    const first = typeNode.namedChildren[0]
    return first ? BROAD_EXCEPT_TYPES.has(first.text) : false
  }
  if (typeNode.type === 'tuple') return typeNode.namedChildren.some((c) => BROAD_EXCEPT_TYPES.has(c.text))
  return false
}

// ---- loose equality ---------------------------------------------------------
const LOOSE_EQ_OPS = new Set(['==', '!='])
const NUMERIC_STRING_VALUE = /^[+-]?(\d+\.?\d*|\.\d+)$/
const NULLISH_TEXT = /^(null|undefined)$/
/** .length/.size/.count are guaranteed numbers — `items.length == 0` behaves
 *  identically to `===`. */
const GUARANTEED_NUMBER_LEAF = /^(length|size|count)$/i

/**
 * A literal whose loose comparison invokes coercion: numbers, empty/whitespace
 * strings, numeric strings, booleans. 'POST'/'per_unit'-style enum strings only
 * loosely equal themselves and are NOT hazardous. `-1` parses as a
 * unary_expression, which numberLiteralValue rejects — silently excluding the
 * legit `indexOf(x) == -1` idiom.
 */
function isCoercionHazardousLiteral(node: SyntaxNode, lang: SastLanguage): boolean {
  if (numberLiteralValue(node, lang) !== null) return true
  const s = stringLiteralValue(node, lang)
  if (s !== null) return /^\s*$/.test(s) || NUMERIC_STRING_VALUE.test(s.trim())
  return boolLiteralValue(node, lang) !== null
}

function isAnyLiteral(node: SyntaxNode, lang: SastLanguage): boolean {
  return (
    numberLiteralValue(node, lang) !== null ||
    stringLiteralValue(node, lang) !== null ||
    boolLiteralValue(node, lang) !== null
  )
}

// ---- database query inside a loop (N+1) ------------------------------------
/** ORM/query-builder READ methods. Writes are deliberately absent — that alone
 *  excludes every seed/migration/backfill loop swept. */
const DB_READ_METHODS = new Set([
  'findunique', 'finduniqueorthrow', 'findfirst', 'findfirstorthrow', 'findmany',
  'findone', 'findall', 'findbyid', 'findbypk', 'count', 'aggregate', 'groupby',
])
const LOOP_TYPES = new Set(['for_statement', 'for_in_statement', 'while_statement', 'do_statement'])
/** Loop variables that name deliberate batching (`for (const chunk of chunks)`). */
const BATCH_LOOP_VAR = /^(chunk|batch|page|group|slice|part|partition|window|bucket)(e?s)?$/i

/** identifier / destructuring-leaf names under a node (loop-variable patterns). */
function identifierLeaves(node: SyntaxNode): string[] {
  const out: string[] = []
  walk(node, (n) => {
    if (n.type === 'identifier' || n.type === 'shorthand_property_identifier_pattern') out.push(n.text)
  })
  return out
}

/** True when the subtree references any of the given names. */
function referencesAny(node: SyntaxNode, names: Set<string>): boolean {
  let found = false
  walk(node, (n) => {
    if (!found && (n.type === 'identifier' || n.type === 'shorthand_property_identifier') && names.has(n.text)) {
      found = true
    }
  })
  return found
}

function containsNumberLiteral(node: SyntaxNode, lang: SastLanguage): boolean {
  let found = false
  walk(node, (n) => {
    if (!found && numberLiteralValue(n, lang) !== null) found = true
  })
  return found
}

/**
 * Per-iteration dependence — the actual N+1 signature. D = loop vars plus names
 * bound BEFORE the call by a declarator/assignment whose value references a name
 * already in D (`const user = teamMembers[i]`). Single forward pass, skipping
 * nested-function subtrees.
 */
function perIterationNames(
  body: SyntaxNode,
  loopVars: string[],
  callNode: SyntaxNode,
  lang: SastLanguage,
): Set<string> {
  const derived = new Set(loopVars)
  const visit = (n: SyntaxNode) => {
    if (n !== body && isFunctionNode(n, lang)) return
    if (n.startIndex < callNode.startIndex) {
      if (n.type === 'variable_declarator') {
        const nameNode = n.childForFieldName('name')
        const value = n.childForFieldName('value')
        if (nameNode?.type === 'identifier' && value && referencesAny(value, derived)) derived.add(nameNode.text)
      } else if (n.type === 'assignment_expression') {
        const left = n.childForFieldName('left')
        const right = n.childForFieldName('right')
        if (left?.type === 'identifier' && right && referencesAny(right, derived)) derived.add(left.text)
      }
    }
    for (const c of n.namedChildren) visit(c)
  }
  visit(body)
  return derived
}

/** A return, or a break not enclosed by a switch, marks the bounded-lookback
 *  search idiom (per-candidate probe, exit on first hit) — never N+1. */
function loopBodyHasEarlyExit(body: SyntaxNode, loopNode: SyntaxNode, lang: SastLanguage): boolean {
  let exits = false
  const visit = (n: SyntaxNode) => {
    if (exits) return
    if (n !== body && isFunctionNode(n, lang)) return
    if (n.type === 'return_statement') {
      exits = true
      return
    }
    if (n.type === 'break_statement' && !breakEnclosedBySwitch(n, loopNode)) {
      exits = true
      return
    }
    for (const c of n.namedChildren) visit(c)
  }
  visit(body)
  return exits
}

function breakEnclosedBySwitch(brk: SyntaxNode, loopNode: SyntaxNode): boolean {
  // web-tree-sitter wrappers are not identity-stable — compare by node id.
  let cur = brk.parent
  for (let i = 0; i < 40 && cur && cur.id !== loopNode.id; i++) {
    if (cur.type === 'switch_statement') return true
    cur = cur.parent
  }
  return false
}

// ---- mass assignment --------------------------------------------------------
const MA_WRITE_METHODS = new Set(['create', 'update', 'upsert', 'updatemany', 'createmany'])
/** DB_RECEIVER extended with transaction-callback names for WRITE receivers. */
const MA_TX_RECEIVER = /(^|[._])(tx|trx)([._]|$)/i
/** Rule-local accepted request roots/props — narrower than the taint engine's:
 *  headers/url/data/args/params/searchParams are deliberately excluded
 *  (schema-declared or server-to-server, not arbitrary-key client payloads). */
const MA_REQUEST_ROOTS = new Set(['req', 'request', 'ctx', 'context', 'httprequest', 'httpcontext'])
const MA_REQUEST_PROPS = new Set(['body', 'rawbody', 'form', 'formdata', 'files', 'post', 'query'])
/** An explicit open-record annotation: the author declaring arbitrary-key
 *  pass-through. Named model types, Partial<T>, and field literals never match. */
const OPEN_RECORD_TYPE = /^(any|unknown|object|Record<string,(unknown|any)>)$|^\{\[/

function isDbWriteReceiver(name: string | null): boolean {
  if (!name) return false
  return DB_RECEIVER.test(name) || MA_TX_RECEIVER.test(name)
}

/** Arm (a): the expression IS the raw request payload — req.json()/req.body. */
function isDirectRequestSource(node: SyntaxNode, lang: SastLanguage): boolean {
  const n = unwrap(node, lang)
  const call = asCall(n, lang)
  if (call) {
    const m = lc(call.method)
    if (m !== 'json' && m !== 'text' && m !== 'formdata') return false
    const recv = lc(call.receiverName ?? '')
    const last = recv.slice(recv.lastIndexOf('.') + 1)
    return last === 'req' || last === 'request'
  }
  const dotted = lc(dottedName(n, lang) ?? '')
  const segs = dotted.split('.')
  if (segs.length < 2) return false
  return MA_REQUEST_ROOTS.has(segs[0]) && MA_REQUEST_PROPS.has(segs[segs.length - 1])
}

/** Payload expressions in mass-assignment sink position for this call. */
function massAssignPayloads(call: NCall, lang: SastLanguage): SyntaxNode[] {
  const m = lc(call.method)
  const out: SyntaxNode[] = []
  // P1 prisma-style: db.model.update({ …, data: E }) (upsert also create/update)
  if (MA_WRITE_METHODS.has(m) && isDbWriteReceiver(call.receiverName)) {
    const arg0 = call.args[0]
    if (arg0?.type === 'object') {
      const keys = m === 'upsert' ? ['data', 'create', 'update'] : ['data']
      for (const child of arg0.namedChildren) {
        if (child.type === 'pair') {
          const key = lc(child.childForFieldName('key')?.text ?? '').replace(/['"]/g, '')
          const value = child.childForFieldName('value')
          if (value && keys.includes(key)) out.push(value)
        } else if (child.type === 'shorthand_property_identifier' && keys.includes(lc(child.text))) {
          out.push(child)
        }
      }
    }
  }
  // P2 drizzle-style: db.insert(t).values(E) / db.update(t).set(E)
  if (m === 'values' || m === 'set') {
    const recvCall = call.receiver ? asCall(unwrap(call.receiver, lang), lang) : null
    const rm = recvCall ? lc(recvCall.method) : ''
    if (recvCall && (rm === 'insert' || rm === 'update') && isDbWriteReceiver(recvCall.receiverName) && call.args[0]) {
      out.push(call.args[0])
    }
  }
  // P3 supabase/knex-style: supabase.from('t').update(E) / db('t').update(E)
  if (m === 'insert' || m === 'update' || m === 'upsert') {
    const recvCall = call.receiver ? asCall(unwrap(call.receiver, lang), lang) : null
    if (((recvCall && lc(recvCall.method) === 'from') || isDbWriteReceiver(call.receiverName)) && call.args[0]) {
      out.push(call.args[0])
    }
  }
  return out
}

interface MassAssignBinding {
  kind: 'defs' | 'param'
  /** Value nodes of every def in the binding scope (kind 'defs'). */
  defs: SyntaxNode[]
  /** The binding function node; null when bound at the program root. */
  fnNode: SyntaxNode | null
}

/**
 * Lexical binding resolution for a bare identifier: walk enclosing function
 * scopes innermost→outermost (program root last); the first scope binding the
 * name — via defs (collectAssignments semantics) or as a declared parameter —
 * is the binding scope. Defs take precedence over a same-named parameter.
 */
function resolveMassAssignBinding(
  from: SyntaxNode,
  name: string,
  lang: SastLanguage,
): MassAssignBinding | null {
  let cur: SyntaxNode | null = from.parent
  for (let i = 0; i < 60 && cur; i++) {
    const isRoot = cur.parent === null
    if (isFunctionNode(cur, lang) || isRoot) {
      const fn = isFunctionNode(cur, lang) ? asFunction(cur, lang) : null
      const body = isRoot && !fn ? cur : fn?.body
      const defs = body
        ? collectAssignments(body, lang).filter((a) => a.target === name).map((a) => a.value)
        : []
      if (defs.length > 0) return { kind: 'defs', defs, fnNode: fn ? cur : null }
      if (fn && fn.params.includes(name)) return { kind: 'param', defs: [], fnNode: cur }
    }
    cur = cur.parent
  }
  return null
}

/** Whether the named parameter of fnNode carries an explicit open-record type
 *  annotation. A MISSING annotation never fires (plain-JS helpers). */
function hasOpenRecordAnnotation(fnNode: SyntaxNode, name: string): boolean {
  const params = fnNode.childForFieldName('parameters')
  if (!params) return false
  for (const p of params.namedChildren) {
    const pattern = p.childForFieldName('pattern') ?? p.childForFieldName('name')
    if (pattern?.type !== 'identifier' || pattern.text !== name) continue
    const typeNode = p.childForFieldName('type')
    if (!typeNode) return false
    const normalized = typeNode.text.replace(/^:\s*/, '').replace(/\s+/g, '')
    return OPEN_RECORD_TYPE.test(normalized)
  }
  return false
}

/** Which arm (if any) marks this payload expression as a raw request object. */
function massAssignArm(s: SyntaxNode, sinkNode: SyntaxNode, lang: SastLanguage): string | null {
  const n = unwrap(s, lang)
  // (a) inline request source: data: req.body / data: await req.json()
  if (isDirectRequestSource(n, lang)) return 'request source'
  // A shorthand `data` property references the binding of the same name.
  const name = identifierName(n, lang) ?? (n.type === 'shorthand_property_identifier' ? n.text : null)
  if (!name) return null // call results, arrays, ternaries, … never fire
  const binding = resolveMassAssignBinding(sinkNode, name, lang)
  if (!binding) return null
  if (binding.kind === 'defs') {
    // (b) flow-insensitive and FN-biased: EVERY def must be a direct request
    // source — any validating reassignment (schema.parse) suppresses entirely.
    return binding.defs.every((v) => isDirectRequestSource(v, lang)) ? 'request-sourced local' : null
  }
  // (c) open-record parameter: the annotation itself declares arbitrary-key
  // pass-through into a write — the report-worthy contract.
  return binding.fnNode && hasOpenRecordAnnotation(binding.fnNode, name) ? 'open-record parameter' : null
}

export const PATTERN_RULES: PatternRule[] = [
  // ---- Server secret inlined into the browser bundle ----
  {
    id: 'client-exposed-secret',
    cweKey: 'CLIENTSECRET',
    severity: 'HIGH',
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Server secret exposed to the browser bundle',
    message:
      'A server-only credential is read through a public build prefix, so the bundler inlines its value into JavaScript every visitor downloads. Prefixing a variable to silence an "undefined" error publishes the secret.',
    remediation:
      'Drop the public prefix and read this variable only in server code (route handler, server component, or server action). Rotate the credential — assume any value already shipped in a bundle is compromised.',
    test(node, lang) {
      if (!asMember(node, lang)) return []
      const dotted = dottedName(node, lang)
      if (!dotted) return []
      const last = dotted.slice(dotted.lastIndexOf('.') + 1)
      // Case-sensitive: these prefixes are uppercase by build-tool convention.
      if (!CLIENT_ENV_PREFIX.test(last) || !SERVER_ONLY_ENV_NAME.test(last)) return []
      return [{ node, line: node.startPosition.row + 1, detail: last }]
    },
  },

  // ---- Insecure deserialization (dangerous-by-format) ----
  {
    id: 'insecure-deserialization',
    cweKey: 'DESER',
    severity: 'HIGH',
    languages: ALL,
    title: 'Insecure deserialization',
    message: 'An inherently unsafe deserializer is used. These formats can instantiate arbitrary types on load, enabling remote code execution if the data is ever attacker-influenced.',
    remediation: 'Use a safe format (JSON) or the safe API variant (yaml.safe_load, allowed_classes, a validating binder); never deserialize untrusted data with these.',
    test(node, lang) {
      const call = asCall(node, lang)
      if (!call) return []
      const full = lc(call.fullName)
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      // Python
      if (/^(pickle|cpickle|_pickle|dill)\.(loads?|load)$/.test(full)) return [{ node, line: call.line, detail: 'pickle' }]
      if (/marshal\.loads?$/.test(full)) return [{ node, line: call.line, detail: 'marshal' }]
      if (full === 'yaml.load') {
        // safe only when an explicit SafeLoader is passed
        const loader = findOption(call, lang, 'loader')
        const loaderText = loader ? lc(loader.text) : lc(call.args[1]?.text)
        if (!/safeloader|safe_load/.test(loaderText)) return [{ node, line: call.line, detail: 'yaml.load' }]
        return []
      }
      // Java — ObjectInputStream.readObject() (any receiver; readObject is specific)
      if (m === 'readobject' && call.receiverName) return [{ node, line: call.line, detail: 'ObjectInputStream' }]
      // Ruby
      if (full === 'marshal.load' || (m === 'load' && recv === 'yaml' && lang === 'ruby')) return [{ node, line: call.line, detail: recv }]
      // C# — dangerous formatters (construct or Deserialize call)
      if (call.isConstruct && /binaryformatter|soapformatter|netdatacontractserializer|losformatter|objectstateformatter/i.test(call.fullName)) {
        return [{ node, line: call.line, detail: call.fullName }]
      }
      if (m === 'deserialize' && /binaryformatter|soapformatter|losformatter/.test(recv)) {
        return [{ node, line: call.line, detail: call.receiverName ?? '' }]
      }
      return []
    },
  },

  // ---- Weak hash ----
  {
    id: 'weak-hash',
    cweKey: 'WEAKHASH',
    severity: 'MEDIUM',
    languages: ALL,
    title: 'Weak cryptographic hash (MD5/SHA-1)',
    message: 'MD5/SHA-1 are broken for security purposes (collisions are practical). Using them for signatures, integrity, or password hashing is unsafe.',
    remediation: 'Use SHA-256/SHA-3 for integrity, and a dedicated password hash (bcrypt/scrypt/Argon2) for passwords.',
    test(node, lang) {
      const call = asCall(node, lang)
      if (!call) return []
      const m = lc(call.method)
      const recv = lc(call.receiverName)
      const arg0 = call.args[0] ? lc(stringLiteralValue(call.args[0], lang) ?? '') : ''
      const isWeak =
        (m === 'createhash' && /^(md5|sha1|sha-1)$/.test(arg0)) ||
        (m === 'getinstance' && /^(md5|sha-?1)$/.test(arg0)) ||
        ((m === 'md5' || m === 'sha1') && (recv === 'hashlib' || recv === '' || recv === 'digest')) ||
        /^(md5|sha1)\.create$/.test(lc(call.fullName))
      if (!isWeak) return []
      // Suppress non-security content hashing (fingerprint/dedup/ETag/identity).
      if (isNonSecurityHash(node, lang)) return []
      const detail = m === 'createhash' || m === 'getinstance' ? arg0 : m
      return [{ node, line: call.line, detail }]
    },
  },

  // ---- Weak cipher (DES / ECB / RC4) ----
  {
    id: 'weak-cipher',
    cweKey: 'WEAKCIPHER',
    severity: 'MEDIUM',
    languages: ALL,
    title: 'Weak or misused cipher (DES / ECB / RC4)',
    message: 'A broken cipher (DES/RC4) or the ECB mode is selected. ECB leaks plaintext structure; DES/RC4 are cryptographically broken.',
    remediation: 'Use AES-256 in an authenticated mode (GCM) with a random IV/nonce.',
    test(node, lang) {
      const call = asCall(node, lang)
      if (!call) return []
      const m = lc(call.method)
      if (!/createcipher|createcipheriv|createdecipheriv|getinstance|new/.test(m) && !call.isConstruct) return []
      const arg0 = stringLiteralValue(call.args[0], lang)
      if (!arg0) return []
      if (/(^|[-/_])(des|des-ede|rc4|ecb)([-/_]|$)/i.test(arg0)) return [{ node, line: call.line, detail: arg0 }]
      return []
    },
  },

  // ---- Insecure PRNG for a secret ----
  {
    id: 'insecure-randomness',
    cweKey: 'WEAKRNG',
    severity: 'MEDIUM',
    languages: ALL,
    title: 'Insecure randomness used for a secret',
    message: 'A non-cryptographic PRNG (Math.random / random / rand) is used to generate a security-sensitive value. Its output is predictable and can be brute-forced.',
    remediation: 'Use a CSPRNG: crypto.randomBytes / secrets.token_bytes / RNGCryptoServiceProvider / SecureRandom.',
    test(node, lang) {
      const call = asCall(node, lang)
      if (!call) return []
      const full = lc(call.fullName)
      const isWeak =
        full === 'math.random' ||
        /^random\.(random|randint|randrange|getrandbits|choice)$/.test(full) ||
        (call.isConstruct && /^random$/i.test(call.fullName)) ||
        full === 'rand'
      if (!isWeak) return []
      const ctx = nameContext(node, lang, RNG_NAME)
      return ctx ? [{ node, line: call.line, detail: ctx }] : []
    },
  },

  // ---- Disabled TLS / certificate validation ----
  {
    id: 'disabled-tls-validation',
    cweKey: 'TLS',
    severity: 'HIGH',
    languages: ALL,
    title: 'Disabled TLS certificate validation',
    message: 'TLS certificate/hostname verification is turned off, exposing the connection to man-in-the-middle attacks.',
    remediation: 'Never disable certificate validation. Fix the trust store / pin the correct CA instead.',
    test(node, lang) {
      const nv = asNamedValue(node, lang)
      if (nv) {
        const n = nv.name
        if (n === 'rejectunauthorized' && boolLiteralValue(nv.value, lang) === false) return [{ node, line: node.startPosition.row + 1, detail: n }]
        if (n === 'insecureskipverify' && boolLiteralValue(nv.value, lang) === true) return [{ node, line: node.startPosition.row + 1, detail: n }]
        if (n === 'verify' && boolLiteralValue(nv.value, lang) === false && lang === 'python') return [{ node, line: node.startPosition.row + 1, detail: n }]
        // C#: xyz.ServerCertificateValidationCallback = (…) => true
        if (/servercertificatevalidationcallback|remotecertificatevalidationcallback|servercertificatecustomvalidationcallback/.test(n)) {
          if (/=>\s*true|return\s+true/.test(nv.value.text)) return [{ node, line: node.startPosition.row + 1, detail: n }]
        }
      }
      return []
    },
  },

  // ---- Hard-coded credentials (complements the regex secrets analyzer) ----
  {
    id: 'hardcoded-credentials',
    cweKey: 'HARDCRED',
    severity: 'HIGH',
    languages: ALL,
    title: 'Hard-coded credential',
    message: 'An API key / token / secret is assigned a literal string in source. Committed credentials must be treated as compromised.',
    remediation: 'Load the credential from environment/secret storage and rotate the exposed value.',
    test(node, lang) {
      const nv = asNamedValue(node, lang)
      if (!nv) return []
      if (!SECRET_NAME.test(nv.name)) return []
      const val = stringLiteralValue(nv.value, lang)
      if (!val || val.length < 8) return []
      if (CRED_PLACEHOLDER.test(val) || CRED_PLACEHOLDER.test(nv.value.text)) return []
      // A credential is a single token; internal whitespace means display text
      // (an error message keyed by credential name), not a secret.
      if (/\s/.test(val)) return []
      if (CRED_LABEL_VALUE.test(val)) return [] // header/param NAME or bare prefix, not a secret
      if (isNonCredentialUrlLiteral(val)) return []
      return [{ node, line: node.startPosition.row + 1, detail: nv.name }]
    },
  },

  // ---- XXE ----
  {
    id: 'xxe',
    cweKey: 'XXE',
    severity: 'HIGH',
    languages: new Set<SastLanguage>(['csharp', 'python', 'java']),
    title: 'XML external entity (XXE) processing enabled',
    message: 'An XML parser is configured to resolve external entities/DTDs, allowing file disclosure and SSRF via crafted XML.',
    remediation: 'Disable DTD/external-entity processing (DtdProcessing.Prohibit, resolve_entities=False, XMLConstants FEATURE_SECURE_PROCESSING).',
    test(node, lang) {
      // C#: DtdProcessing.Parse
      const m = asMember(node, lang)
      if (m && lang === 'csharp') {
        const dotted = lc(dottedName(node, lang) ?? '')
        if (dotted === 'dtdprocessing.parse') return [{ node, line: node.startPosition.row + 1, detail: dotted }]
      }
      // Python lxml: resolve_entities=True
      const nv = asNamedValue(node, lang)
      if (nv && nv.name === 'resolve_entities' && boolLiteralValue(nv.value, lang) === true) {
        return [{ node, line: node.startPosition.row + 1, detail: nv.name }]
      }
      // C#: XmlResolver = new XmlUrlResolver()
      if (nv && nv.name === 'xmlresolver' && /xmlurlresolver/i.test(nv.value.text)) {
        return [{ node, line: node.startPosition.row + 1, detail: nv.name }]
      }
      return []
    },
  },

  // ---- Insecure cookie flags ----
  {
    id: 'insecure-cookie',
    cweKey: 'COOKIE',
    severity: 'MEDIUM',
    languages: ALL,
    title: 'Insecure cookie flag',
    message: 'A cookie is set with HttpOnly or Secure explicitly disabled, exposing it to theft via XSS or plaintext interception.',
    remediation: 'Set cookies with httpOnly: true and secure: true (and SameSite) for session/auth cookies.',
    test(node, lang) {
      const nv = asNamedValue(node, lang)
      if (!nv) return []
      if ((nv.name === 'httponly' || nv.name === 'secure') && boolLiteralValue(nv.value, lang) === false) {
        if (callContext(node, lang, /cookie|session/i)) return [{ node, line: node.startPosition.row + 1, detail: nv.name }]
      }
      return []
    },
  },

  // ---- Timing-unsafe secret comparison ----
  {
    id: 'timing-unsafe-compare',
    cweKey: 'TIMING',
    severity: 'LOW',
    languages: ALL,
    title: 'Timing-unsafe secret comparison',
    message: 'A secret (key, signature, password) is compared with a standard equality operator. String comparison short-circuits on the first differing byte, letting an attacker recover the value byte-by-byte from response timing.',
    remediation: 'Compare with a constant-time primitive — crypto.timingSafeEqual (Node), hmac.compare_digest (Python) — after a length guard, or compare HMAC digests of both sides.',
    test(node, lang) {
      const t = node.type
      if (t !== 'binary_expression' && t !== 'comparison_operator' && t !== 'binary') return []
      const op =
        node.childForFieldName('operator')?.text ??
        node.children.find((c) => EQ_OPS.has(c.type))?.text
      if (!op || !EQ_OPS.has(op)) return []
      const left = node.childForFieldName('left') ?? node.namedChildren[0]
      const right = node.childForFieldName('right') ?? node.namedChildren[1]
      if (!left || !right) return []
      if (isTrivialCompareOperand(left, lang) || isTrivialCompareOperand(right, lang)) return []
      const hit = secretCompareSide(left, lang) ?? secretCompareSide(right, lang)
      if (!hit) return []
      // Only password-ish hits get the same-user idiom passes, so a secret
      // like confirmationToken elsewhere keeps its protection.
      if (PASSWORD_NAME.test(hit)) {
        const sides = [left, right].map((side) => {
          const u = unwrap(side, lang)
          return dottedName(u, lang) ?? identifierName(u, lang) ?? ''
        })
        if (sides.some((sideName) => CONFIRMATION_NAME.test(sideName))) return []
        if (sides.some((sideName) => FORM_SIBLING_FIELD.test(sideName))) return []
        if (
          sides.every((sideName) => PASSWORD_NAME.test(sideName)) &&
          sides.some((sideName) => SAME_USER_PASSWORD_PREFIX.test(sideName))
        )
          return []
      }
      return [{ node, line: node.startPosition.row + 1, detail: hit }]
    },
  },

  // ---- Weak RSA/DSA key size ----
  {
    id: 'weak-key-size',
    cweKey: 'WEAKCIPHER',
    severity: 'MEDIUM',
    languages: ALL,
    title: 'Weak asymmetric key size',
    message: 'An RSA/DSA key smaller than 2048 bits is generated; such keys are considered breakable.',
    remediation: 'Generate RSA/DSA keys of at least 2048 bits (prefer 3072+), or use an elliptic-curve key.',
    test(node, lang) {
      const call = asCall(node, lang)
      if (!call) return []
      const m = lc(call.method)
      if (!/initialize|generatekeypair|generate|moduluslength/.test(m) && !/modulus_size|key_size/.test(lc(call.fullName))) return []
      for (const a of call.args) {
        const n = numberLiteralValue(a, lang)
        if (n !== null && n > 0 && n < 2048) {
          // Require a genuine key-generation context. A bare `generat` match flags
          // business helpers like generateCoupon(15)/generateOtp(6)/generateId(8)
          // where the number is a percent/length, not a key modulus.
          if (/key|rsa|dsa|modulus/i.test(call.fullName) || m === 'initialize') return [{ node, line: call.line, detail: String(n) }]
        }
      }
      return []
    },
  },

  // ---- Un-awaited database write (floating promise) ----
  {
    id: 'unawaited-persistence',
    cweKey: 'UNAWAITED',
    severity: 'MEDIUM',
    // JS family only: sync SQLAlchemy `session.commit()` is byte-identical to
    // the async-bug shape and legitimate — Python is not deterministically
    // separable, so it stays out.
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Un-awaited database write (floating promise)',
    message:
      'A database write is started and its promise is discarded — neither awaited, returned, handled with .then/.catch, nor explicitly voided. If the write fails the error is silently lost and the caller proceeds as if it succeeded; the surrounding function can return before the write completes. For lazy clients (Drizzle, Prisma $executeRaw, Convex) the query may never execute at all.',
    remediation:
      'Await the call (or return the promise to a caller that awaits it). If fire-and-forget is genuinely intended, make it explicit: attach .catch() with error logging, or prefix the statement with the void operator after attaching a rejection handler.',
    test(node, lang) {
      if (node.type !== 'expression_statement') return []
      // The FIRST NAMED CHILD must be the call itself. unwrap() is deliberately
      // NOT used: it strips await_expression, and `await` is exactly what must
      // keep excluding. Return position, assignment, void, yield, argument
      // position and implicit arrow returns all fail this anchor structurally.
      const child = node.namedChildren[0]
      if (!child || child.type !== 'call_expression') return []
      const call = asCall(child, lang)
      if (!call || call.isConstruct) return []
      const m = lc(call.method)
      const recv = lc(call.receiverName ?? '')
      const recvCore = stripContextSegment(recv)
      const fullCore = stripContextSegment(lc(call.fullName))
      const hit = [{ node: child, line: call.line, detail: call.fullName }]

      // A. ORM-model write (Prisma/Mongo style): db.<model>.<writeVerb>(…)
      const segs = recvCore.split('.')
      if (
        segs.length >= 2 &&
        FLOATING_DB_ROOTS.has(segs[0]) &&
        ORM_WRITE_METHODS.has(m) &&
        receiverChainCallFree(call.receiver, lang)
      ) {
        if (!DELETEISH_METHODS.has(m) || call.args.length === 0 || call.args[0].type === 'object') return hit
      }
      // B. Lazy query-builder chain (Drizzle/Knex): a write verb called
      // DIRECTLY on the db root plus at least one chained call — these
      // builders are lazy thenables, so a floating chain never executes.
      if (/^(db|tx|trx|database)\.(insert|update|delete)\.[a-z_$]/.test(fullCore) && !PROMISE_TERMINALS.has(m)) {
        return hit
      }
      // C. Prisma raw write escape hatch — PrismaPromise is lazy, a floating
      // $executeRaw never runs. (asMember strips the leading '$'.)
      if (segs.length === 1 && FLOATING_DB_ROOTS.has(segs[0]) && (m === 'executeraw' || m === 'executerawunsafe')) {
        return hit
      }
      // D. Convex mutations, gated to the literal `ctx.db` convention so
      // `this.db.delete(key)` on a Map-holding class can never fire.
      if (recv === 'ctx.db' && CONVEX_WRITE_METHODS.has(m)) return hit
      // E. Raw driver write: `pool.query("INSERT …")` with the promise dropped.
      // The commonest floating-write shape in Express/pg code, and invisible to
      // the ORM arms above. Four independent gates keep it exact: a DB-shaped
      // receiver, a SQL string whose first keyword is a WRITE (a dropped SELECT
      // wastes a read; it does not lose data), no function argument — a callback
      // means the callback driver API, which returns nothing to await — and no
      // call inside the receiver chain.
      if (
        RAW_QUERY_METHODS.has(m) &&
        DB_RECEIVER.test(call.receiverName ?? '') &&
        isSqlWriteArgument(call.args[0], lang) &&
        !call.args.some((argument) => isFunctionNode(unwrap(argument, lang), lang)) &&
        receiverChainCallFree(call.receiver, lang)
      ) {
        return hit
      }
      return []
    },
  },

  // ---- Swallowed error (empty catch block) ----
  {
    id: 'swallowed-error',
    cweKey: 'SWALLOW',
    severity: 'LOW',
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx', 'python']),
    title: 'Swallowed error (empty catch block)',
    message:
      'A catch/except block discards the error with no handling, no logging, and no comment. Failures inside the try body vanish silently — the operation can fail with no signal to callers, logs, or users, which hides real defects and data loss.',
    remediation:
      'Handle or at least log the error. If ignoring it is deliberate, document that with a comment inside the catch block (or catch the specific expected exception type in Python) — that records intent and silences this finding.',
    test(node, lang) {
      if (lang === 'python') {
        if (node.type !== 'except_clause') return []
        // A comment before `pass` attaches to the except_clause itself, not to
        // the block — any comment under the clause is documented intent.
        if (node.namedChildren.some((c) => c.type === 'comment')) return []
        const block = node.namedChildren.find((c) => c.type === 'block')
        if (!block) return []
        const stmts = block.namedChildren
        // A trailing `pass  # ok` comment lands inside the block → length 2.
        if (stmts.length !== 1 || stmts[0].type !== 'pass_statement') return []
        const typeNode = node.namedChildren.find((c) => c.type !== 'block' && c.type !== 'comment')
        if (typeNode && !isBroadExceptType(typeNode)) return []
        const tryNode = node.parent
        if (tryNode) {
          if (tryHasAdjacentComment(tryNode, node.endPosition.row)) return []
          if (isBestEffortCleanup(tryNode, lang)) return []
        }
        const detail = tryNode ? firstTryBodyCall(tryNode, lang)?.fullName : undefined
        return [{ node, line: node.startPosition.row + 1, detail }]
      }
      if (node.type !== 'catch_clause') return []
      const body = node.childForFieldName('body')
      if (!body) return []
      // Comments are named nodes in this grammar: `catch { // ignore }` is NOT
      // empty, so comment-only catches (the dominant legit idiom) never fire.
      // `catch {;}` contains only empty_statement nodes and is still empty.
      if (!body.namedChildren.every((c) => c.type === 'empty_statement')) return []
      const tryNode = node.parent
      if (tryNode) {
        if (tryHasAdjacentComment(tryNode, node.endPosition.row)) return []
        if (isBestEffortCleanup(tryNode, lang)) return []
      }
      const detail = tryNode ? firstTryBodyCall(tryNode, lang)?.fullName : undefined
      return [{ node, line: node.startPosition.row + 1, detail }]
    },
  },

  // ---- Loose equality against a coercion-prone literal ----
  {
    id: 'loose-equality',
    cweKey: 'LOOSEEQ',
    severity: 'MEDIUM',
    // Python `==` has no coercion — excluded.
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Loose equality against a coercion-prone literal',
    message:
      "A value is compared to a number, empty-string, numeric-string, or boolean literal with == or !=, which applies JavaScript type coercion before comparing: '0' == 0, '' == 0, false == 0, '1' == true, and 0 == '' are all true. A string that arrives where a number was expected — a query parameter, JSON field, or form value — silently passes or fails this check, so a guard like `amount == 0` treats the string '0' (and '' and false) as zero.",
    remediation:
      'Use strict equality (=== / !==) so the type is checked along with the value. If both representations are genuinely expected, normalize explicitly first — Number(x) === 0 — instead of relying on coercion. The one deliberate loose comparison, x == null (matching null and undefined together), is recognized and never flagged.',
    test(node, lang) {
      if (node.type !== 'binary_expression') return []
      const op =
        node.childForFieldName('operator')?.text ??
        node.children.find((c) => LOOSE_EQ_OPS.has(c.type))?.text
      if (!op || !LOOSE_EQ_OPS.has(op)) return []
      const leftRaw = node.childForFieldName('left') ?? node.namedChildren[0]
      const rightRaw = node.childForFieldName('right') ?? node.namedChildren[1]
      if (!leftRaw || !rightRaw) return []
      const left = unwrap(leftRaw, lang)
      const right = unwrap(rightRaw, lang)
      // `x == null` / `x != undefined` is the one deliberate loose idiom.
      if (NULLISH_TEXT.test(left.text) || NULLISH_TEXT.test(right.text)) return []
      const leftHazard = isCoercionHazardousLiteral(left, lang)
      const rightHazard = isCoercionHazardousLiteral(right, lang)
      if (leftHazard === rightHazard) return [] // zero or two hazardous sides
      const literal = leftHazard ? left : right
      const other = leftHazard ? right : left
      if (isAnyLiteral(other, lang)) return [] // constant folding, not a data-coercion bug
      if (/^typeof\b/.test(other.text)) return [] // typeof yields a string — type-safe
      const otherName = dottedName(other, lang)
      if (otherName && GUARANTEED_NUMBER_LEAF.test(otherName.slice(otherName.lastIndexOf('.') + 1))) return []
      return [{ node, line: node.startPosition.row + 1, detail: `${op} ${literal.text}` }]
    },
  },

  // ---- Database query inside a loop (N+1) ----
  {
    id: 'db-call-in-loop',
    cweKey: 'NPLUSONE',
    severity: 'MEDIUM',
    // Python deferred: zero validation evidence in the sweep, and
    // `session.get` collides with dict/web-session .get.
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    excludePath: /(^|\/)(seeds?|migrations?|scripts?|tools|bin)\/|(^|\/)seed\.(ts|js|mjs)$/i,
    title: 'Database query inside a loop (N+1)',
    message:
      'An awaited database read runs inside a loop and its arguments change every iteration — one query per element instead of one batched query (the N+1 pattern). Latency grows linearly with the collection size and the database absorbs N sequential round-trips. This is a signature mistake of AI-generated code that fetches a related record per item.',
    remediation:
      'Batch the per-item lookups into a single query before the loop — findMany with `where: { id: { in: ids } }` (or a groupBy/aggregate) — then join in memory with a Map. If iterations are truly independent and no batch API exists, run them concurrently with Promise.all. If the loop is deliberately sequential over a small bounded set, dismiss this finding; dismissals persist across scans.',
    test(node, lang) {
      const call = asCall(node, lang)
      if (!call || call.isConstruct) return []
      // Read-method gate: ORM reads, or raw-SQL SELECT literals only.
      const m = lc(call.method).replace(/^\$/, '')
      const isRead =
        DB_READ_METHODS.has(m) ||
        ((m === 'query' || m === 'execute') && /^\s*select\b/i.test(stringLiteralValue(call.args[0], lang) ?? ''))
      if (!isRead) return []
      // Receiver gate. DB_RECEIVER does not match tx/trx, so Prisma
      // $transaction callback bodies (intentional-sequential) never fire.
      if (!call.receiverName || !DB_RECEIVER.test(call.receiverName)) return []
      // Await gate: promises pushed for a later Promise.all never fire.
      let parent = node.parent
      while (parent && parent.type === 'parenthesized_expression') parent = parent.parent
      if (!parent || parent.type !== 'await_expression') return []
      // Loop gate: a function boundary before the loop means the call belongs
      // to a callback (.map/Promise.all), not the loop body.
      let loop: SyntaxNode | null = null
      let prev: SyntaxNode = node
      let cur = node.parent
      for (let i = 0; i < 40 && cur; i++) {
        if (isFunctionNode(cur, lang)) return []
        if (LOOP_TYPES.has(cur.type)) {
          loop = cur
          break
        }
        prev = cur
        cur = cur.parent
      }
      if (!loop) return []
      // while/do are cursor-pagination/polling/retry idioms; for-await is the
      // async-iterator row-at-a-time idiom.
      if (loop.type === 'while_statement' || loop.type === 'do_statement') return []
      if (loop.type === 'for_in_statement' && loop.children.some((c) => c.type === 'await')) return []
      // Body-position gate: a query in the for CONDITION (slug-probe idiom)
      // never fires. Wrapper objects are not identity-stable — compare ids.
      const body = loop.childForFieldName('body')
      if (!body || prev.id !== body.id) return []
      let loopVars: string[] = []
      if (loop.type === 'for_in_statement') {
        const right = loop.childForFieldName('right')
        if (right && unwrap(right, lang).type === 'array') return [] // constant bounded iteration
        const left = loop.childForFieldName('left')
        loopVars = left ? identifierLeaves(left) : []
        if (loopVars.some((v) => BATCH_LOOP_VAR.test(v))) return [] // deliberate batching
      } else {
        // for(;;): a numeric-literal bound (`race < 5`) is bounded retry/backoff.
        const condition = loop.childForFieldName('condition')
        if (condition && containsNumberLiteral(condition, lang)) return []
        const initializer = loop.childForFieldName('initializer')
        if (initializer) {
          walk(initializer, (n) => {
            if (n.type === 'variable_declarator') {
              const nameNode = n.childForFieldName('name')
              if (nameNode?.type === 'identifier') loopVars.push(nameNode.text)
            }
          })
        }
      }
      // Per-iteration dependence: a loop-invariant query (retry re-read,
      // constant probe) never fires.
      const derived = perIterationNames(body, loopVars, node, lang)
      if (!call.args.some((a) => referencesAny(a, derived))) return []
      // Early-exit suppression: bounded-lookback search, not N+1.
      if (loopBodyHasEarlyExit(body, loop, lang)) return []
      return [{ node, line: call.line, detail: call.fullName }]
    },
  },

  // ---- Read-modify-write race on a database row (lost update) ----
  {
    id: 'read-modify-write-race',
    cweKey: 'RMWRACE',
    severity: 'MEDIUM',
    // JS family only: the pair search reads Prisma/Drizzle-shaped object
    // arguments, and the key-equality test is unreliable over string-built SQL.
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Read-modify-write on a database row without a transaction',
    message:
      'A row is read, a value from it is recomputed in application code, and the result is written back to the same row in a separate statement. Two requests that interleave between the read and the write both start from the same value, so one update overwrites the other and its change is silently lost — a balance credited twice reads as credited once. Nothing here closes that window: no transaction wraps the pair, and the write sends a computed number rather than an atomic operator.',
    remediation:
      'Let the database do the arithmetic in one statement: Prisma `data: { balance: { increment: amount } }` (or `{ decrement }`), Drizzle or raw SQL `SET balance = balance + $1`. When the new value cannot be expressed as an operator, wrap the read and the write in one interactive transaction that locks the row (`$transaction` plus `SELECT … FOR UPDATE` or an advisory lock), or make the write a compare-and-set — `updateMany({ where: { id, balance: previous }, data: … })` — and retry when it matches zero rows. If this field is deliberately last-write-wins, dismiss this finding; dismissals persist across scans.',
    test(node, lang) {
      return readModifyWriteHits(node, lang, DB_RECEIVER)
    },
  },

  // ---- Mass assignment: request body written wholesale to a DB record ----
  {
    id: 'mass-assignment',
    cweKey: 'MASSASSIGN',
    severity: 'HIGH',
    // No Python: Model(**x) is statically indistinguishable between validating
    // (pydantic/sqlmodel) and raw constructors — firing would FP on the
    // dominant FastAPI idiom.
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Mass assignment: request body written wholesale to a database record',
    message:
      'An object built directly from the raw request body is spread (or passed whole) into a database write payload. Every key the client sends becomes a column update, so an attacker can set fields they should never control (role, orgId, isAdmin, balance) just by adding properties to the JSON body.',
    remediation:
      'Never pass the raw body through to a write. Validate with a schema that strips unknown keys (zod .parse on a non-passthrough object schema) or pick allowed fields explicitly ({ name: body.name, email: body.email }). Do not rely on deleting known-bad keys — a blocklist misses new columns. If a helper must accept partial updates, type it with the model\'s input type, not Record<string, unknown>.',
    test(node, lang) {
      // Arms (a)/(b) only: an actual request object reaches the write. The
      // open-record-parameter arm carries no request evidence and reports
      // separately below, at the severity its evidence supports.
      return massAssignHit(node, lang, (arm) => arm !== 'open-record parameter')
    },
  },

  // ---- Open-record payload contract on a database write ----
  {
    id: 'open-record-write',
    cweKey: 'MASSASSIGN',
    severity: 'MEDIUM',
    languages: new Set<SastLanguage>(['javascript', 'typescript', 'tsx']),
    title: 'Database write helper accepts an open-record payload',
    message:
      'A parameter typed as any/Record<string, unknown> is written wholesale into a database record. The type contract lets every caller-supplied key become a column update, so the helper invites mass assignment even if today’s callers pass safe literals — one new call site fed by request data makes it exploitable.',
    remediation:
      'Type the parameter with the model’s input type (e.g. Prisma.InvoiceUpdateInput) or validate inside the helper with a schema that strips unknown keys. If only fixed fields are ever updated, pick them explicitly instead of spreading the argument.',
    test(node, lang) {
      return massAssignHit(node, lang, (arm) => arm === 'open-record parameter')
    },
  },
]

/** Shared scan for the two mass-assignment-family rules above. */
function massAssignHit(
  node: SyntaxNode,
  lang: SastLanguage,
  wanted: (arm: string) => boolean,
): PatternHit[] {
  const call = asCall(node, lang)
  if (!call || call.isConstruct) return []
  for (const payload of massAssignPayloads(call, lang)) {
    const e = unwrap(payload, lang)
    if (e.type === 'object') {
      // Only DIRECT spread elements count; nested objects and plain pairs
      // (explicit field picking) are ignored.
      for (const child of e.namedChildren) {
        if (child.type !== 'spread_element') continue
        const inner = child.namedChildren[0]
        if (!inner) continue
        const arm = massAssignArm(inner, node, lang)
        if (arm && wanted(arm)) {
          const name = dottedName(unwrap(inner, lang), lang) ?? inner.text.slice(0, 40)
          return [{ node, line: call.line, detail: `${name} (${arm})` }]
        }
      }
    } else {
      const arm = massAssignArm(e, node, lang)
      if (arm && wanted(arm)) {
        const name = dottedName(e, lang) ?? e.text.slice(0, 40)
        return [{ node, line: call.line, detail: `${name} (${arm})` }]
      }
    }
  }
  return []
}

export function ruleAppliesTo(rule: RuleMeta, lang: SastLanguage): boolean {
  return rule.languages === null || rule.languages.has(lang)
}
