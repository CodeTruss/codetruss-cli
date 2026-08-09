import type { SastLanguage, SyntaxNode } from './lang'
import {
  asCall,
  asMember,
  collectAssignments,
  concatOperands,
  dottedName,
  identifierName,
  interpolationExprs,
  paramBoundNames,
  stringLiteralValue,
  subscriptBase,
  unwrap,
  walk,
  type NCall,
  type NFunc,
} from './normalize'

/**
 * Intraprocedural taint analysis with a one-hop interprocedural extension.
 *
 * Approach: within a function we compute, by bounded fixpoint, the set of local
 * variables that carry untrusted data — seeded from SOURCE expressions
 * (request/query/body, argv, env, network reads, …) and propagated through
 * assignments, string concatenation, interpolation, subscripts and non-
 * sanitizing calls. SANITIZERS (parameterizers, escapers, validators, path
 * normalizers) clear taint. We then check every call/construct against the SINK
 * registry: a sink fires only when its dangerous argument is taint-influenced,
 * which is what keeps injection rules high-precision (a constant or parameter-
 * ized argument is never flagged).
 *
 * The analysis is flow-insensitive (a variable assigned a tainted value ANY-
 * where is treated as tainted) — the standard, deterministic lightweight-SAST
 * trade-off. It over-approximates slightly (a var later overwritten with a
 * constant), which is disclosed as a known false-positive vector.
 *
 * Interprocedural: for each function we also record which *parameters* reach a
 * sink; a call passing a tainted argument into such a parameter is reported at
 * the call site with an interprocedural flow. Exactly one hop — bounded and
 * deterministic.
 */

// ---- origins & taint state ------------------------------------------------

export type Origin =
  | { kind: 'source'; sourceKind: string; node: SyntaxNode }
  | { kind: 'param'; index: number; name: string; node: SyntaxNode }

/** A variable's taint = the set of origins that can flow into it. */
type Origins = Origin[]

function mergeOrigins(a: Origins, b: Origins): Origins {
  if (a.length === 0) return b
  if (b.length === 0) return a
  const out = a.slice()
  for (const o of b) {
    const dup = out.some((x) =>
      x.kind === o.kind &&
      (x.kind === 'source' ? x.sourceKind === (o as { sourceKind: string }).sourceKind : (x as { index: number }).index === (o as { index: number }).index),
    )
    if (!dup) out.push(o)
  }
  return out
}

// ---- source / sanitizer detection -----------------------------------------

/** Member-access roots that denote an HTTP request / untrusted-input object. */
const REQUEST_ROOTS = new Set([
  'req', 'request', 'ctx', 'context', 'httprequest', 'httpcontext', 'event', 'args',
  '$_get', '$_post', '$_request', '$_cookie', '$_server', 'params', 'searchparams',
])
/**
 * Request roots whose NAME alone establishes nothing.
 *
 * `event`, `args`, `context`, `params` and `ctx` are ordinary local and loop
 * names in ordinary code. `for (const event of salesforceEvents)` made every
 * `event.<anything>` an untrusted source, so rows already read back from a CRM
 * were treated as attacker input — three CRITICAL injection reports out of one
 * loop variable. So these count as a request object only when the enclosing
 * function BOUND them, positionally or by destructuring.
 *
 * The unambiguous roots are deliberately left ungated: nobody names a loop
 * variable `req`, `httpRequest` or `$_GET`, and a framework that hands a
 * request to a non-parameter binding still reaches those.
 *
 * Recall cost, stated rather than hidden: a handler that destructures its
 * request into a LOCAL named `event` — `const event = JSON.parse(body)` — or a
 * serverless adapter that binds the request through a module-level variable
 * loses the source, and every finding that depended on it. That is a real
 * narrowing, accepted because the name alone was never evidence.
 */
const PARAM_BOUND_REQUEST_ROOTS = new Set(['event', 'args', 'context', 'params', 'ctx'])

/** Names the enclosing function's signature bound, for the ambiguous-root gate. */
export interface TaintScope {
  paramNames: ReadonlySet<string>
}

/**
 * Whether `name` denotes an untrusted request object in the given scope.
 *
 * `scope` is undefined for callers that recognize request SHAPES without a
 * function context (the navigation-target predicate in rules.ts). Those keep
 * the pre-gate answer: they consult this only to decide whether an already-
 * tainted value IS the request rather than something built from it, so
 * narrowing them would change a measured predicate for no stated defect.
 */
function isRequestRoot(name: string, scope?: TaintScope): boolean {
  if (!REQUEST_ROOTS.has(name)) return false
  if (!PARAM_BOUND_REQUEST_ROOTS.has(name)) return true
  return scope ? scope.paramNames.has(name) : true
}
/** Member properties on a request object that expose untrusted data. */
const REQUEST_PROPS = new Set([
  'query', 'body', 'params', 'cookies', 'headers', 'form', 'get', 'post', 'data',
  'url', 'originalurl', 'rawbody', 'files', 'querystring', 'formdata', 'getparameter',
])
/**
 * Whole dotted names that are globally untrusted.
 *
 * NOTE: `process.env` (and the equivalent env-read APIs below) are deliberately
 * NOT sources. Environment variables are operator/deployment configuration, not
 * attacker-controlled input — treating them as taint flags a redirect/URL built
 * from config on nearly every real app (SSRF/open-redirect false positives).
 */
const GLOBAL_SOURCES = new Set([
  'process.argv', 'location.search', 'location.hash', 'location.href',
  'window.name', 'document.cookie', 'document.url', 'document.referrer', 'sys.argv',
  '$_get', '$_post', '$_request', '$_cookie', '$_server', '$_files',
])
/**
 * Go request/context variable names. Go-only: `r`/`c`/`g` are ubiquitous
 * loop and temp names elsewhere, so these are gated behind an accessor
 * whitelist (a member field or method that only a request/context exposes).
 */
const GO_REQUEST_ROOTS = new Set(['r', 'req', 'request', 'c', 'ctx', 'gctx', 'gc', 'ec', 'g'])
/**
 * net/http.Request struct fields that carry untrusted data. Gated on a
 * request-shaped root so `rows.URL`-style false matches cannot occur (these
 * names are specific to *http.Request anyway).
 */
const GO_REQUEST_MEMBERS = new Set([
  'url', 'header', 'body', 'form', 'postform', 'multipartform', 'trailer', 'host', 'requesturi',
])
/**
 * Request/context accessor methods returning untrusted data, gated on a
 * request-shaped receiver. Covers net/http (FormValue, Cookie) and the
 * common frameworks gin/echo/fiber (Query, Param, PostForm, GetHeader).
 */
const GO_REQUEST_METHODS = new Set([
  'formvalue', 'postformvalue', 'cookie', 'referer', 'useragent',
  'query', 'defaultquery', 'querystring', 'param', 'params', 'postform', 'getheader', 'getstring',
])
/** Call names whose *return value* is untrusted input. Matched on last segment. */
const SOURCE_CALL_METHODS = new Set([
  'input', // python input()
  'getparameter', 'getheader', 'getquerystring', 'getinputstream', // java servlet
  'readline', 'readtoend', 'nextline', 'readstring', // console / stream reads
])
/** Full dotted call names that are untrusted sources. */
const SOURCE_CALL_FULLNAMES = new Set([
  'sys.stdin.read', 'sys.stdin.readline',
  'console.readline', 'console.in.readline',
  'request.args.get', 'request.form.get', 'request.values.get', 'request.get_json',
  'request.getparameter', 'request.getheader',
])
/**
 * Reader methods that pull raw bytes/ints off an untrusted stream — the taint
 * source for the CardShopCoop unbounded-BinaryReader deserialization case.
 */
const READER_SOURCE_METHODS = new Set([
  'readint32', 'readint16', 'readint64', 'readuint32', 'readuint16', 'readbyte', 'readbytes', 'readstring',
])
/**
 * Receiver names that denote a binary reader/stream. Includes the idiomatic
 * short abbreviations (`br`, `rdr`) that real C#/Java code uses for a
 * BinaryReader — without these the unbounded-read taint never seeds when the
 * reader isn't literally named "reader"/"stream" (CardShopCoop `var br = ...`).
 */
const READER_RECEIVER = /reader|stream|buffer|^(br|rdr)$/

/** If the expression is an untrusted source, return its kind label. */
export function sourceKindOf(node: SyntaxNode, lang: SastLanguage, scope?: TaintScope): string | null {
  // `await params` / `await searchParams` — Next 15+ async route/page props.
  // Checked on the RAW node because unwrap() strips the await. Awaiting a bare
  // identifier with exactly these names is a strong framework signal; ordinary
  // promises are not named `params`.
  if (node.type === 'await_expression') {
    const inner = identifierName(unwrap(node, lang), lang)?.toLowerCase()
    if (inner === 'params' || inner === 'searchparams') return `await ${inner}`
  }
  const n = unwrap(node, lang)

  // call sources
  const call = asCall(n, lang)
  if (call) {
    const full = call.fullName.toLowerCase()
    const method = call.method.toLowerCase()
    if (SOURCE_CALL_FULLNAMES.has(full)) return full
    if (READER_SOURCE_METHODS.has(method) && READER_RECEIVER.test(call.receiverName?.toLowerCase() ?? '')) {
      return 'network-bytes'
    }
    // Fetch-API/Next.js request body readers — req.json()/req.text()/req.formData().
    // Gated on a request-shaped receiver: a fetch RESPONSE's .json() is the
    // server's own upstream call, not attacker input (flagging it buries real
    // findings in internal-API noise).
    if (
      (method === 'json' || method === 'text' || method === 'formdata') &&
      call.receiverName &&
      isRequestRoot(call.receiverName.toLowerCase(), scope)
    ) {
      return `${call.receiverName}.${method}()`
    }
    // next/headers cookies() — every cookie value is attacker-controlled.
    // useSearchParams()/useParams() — the client-side equivalents: both read
    // straight off the URL. These are named here rather than inferred from the
    // variable they land in, which is what makes the parameter-binding gate on
    // `params` affordable: `const params = useSearchParams()` is a local, so
    // the name proves nothing, but the CALL proves everything.
    if (
      (method === 'cookies' || method === 'usesearchparams' || method === 'useparams') &&
      !call.receiverName &&
      !call.isConstruct &&
      (lang === 'javascript' || lang === 'typescript' || lang === 'tsx')
    ) {
      return method === 'cookies' ? 'cookies()' : `${call.method}()`
    }
    // Getter calls on a request-shaped root: searchParams.get('q'),
    // params.get(…). The member branch below already treats `<root>.anything`
    // as a source, so this adds no exposure the member form doesn't have.
    if (method === 'get' && call.receiverName && isRequestRoot(call.receiverName.toLowerCase(), scope)) {
      return `${call.receiverName}.get`
    }
    // bare input() in python
    if (lang === 'python' && method === 'input' && !call.receiverName) return 'stdin'
    if (SOURCE_CALL_METHODS.has(method) && call.receiverName) return `${call.receiverName}.${method}`
    if (lang === 'go') {
      const recv = call.receiverName?.toLowerCase()
      // r.FormValue(), c.Query(), c.Param(), r.Cookie(), c.GetHeader()...
      if (recv && GO_REQUEST_ROOTS.has(recv) && GO_REQUEST_METHODS.has(method)) {
        return `${recv}.${method}`
      }
      // gorilla/mux path variables: mux.Vars(r) → map[string]string
      if (recv === 'mux' && method === 'vars') return 'mux.vars'
    }
    return null
  }

  // member / subscript sources
  const dotted = dottedName(n, lang)?.toLowerCase()
  if (dotted && GLOBAL_SOURCES.has(dotted)) return dotted
  const m = asMember(n, lang) ?? (subscriptBase(n) ? asMember(subscriptBase(n)!, lang) : null)
  if (m) {
    const rootName = rootIdentifier(n, lang)?.toLowerCase()
    const prop = m.property.toLowerCase()
    if (rootName && isRequestRoot(rootName, scope) && REQUEST_PROPS.has(prop)) return `${rootName}.${prop}`
    if (rootName && isRequestRoot(rootName, scope)) return rootName // req.<anything>.x
    // Go: r.URL / r.Header / r.Body etc. — request fields, gated on a
    // request-shaped root so a *sql.Rows named `r` is not caught.
    if (lang === 'go' && rootName && GO_REQUEST_ROOTS.has(rootName) && GO_REQUEST_MEMBERS.has(prop)) {
      return `${rootName}.${prop}`
    }
    // php superglobal subscript: $_GET['x']
    if (rootName && GLOBAL_SOURCES.has(rootName)) return rootName
  }
  // bare php superglobal reference $_GET / subscript base
  const rid = rootIdentifier(n, lang)?.toLowerCase()
  if (rid && GLOBAL_SOURCES.has(rid)) return rid
  return null
}

/** Left-most identifier of a member/subscript chain. */
function rootIdentifier(node: SyntaxNode, lang: SastLanguage): string | null {
  let cur: SyntaxNode | null = unwrap(node, lang)
  for (let i = 0; i < 20 && cur; i++) {
    const m = asMember(cur, lang)
    if (m) {
      cur = m.object
      continue
    }
    const sub = subscriptBase(cur)
    if (sub) {
      cur = sub
      continue
    }
    const call = asCall(cur, lang)
    if (call && call.receiver) {
      cur = call.receiver
      continue
    }
    return identifierName(cur, lang) ?? (cur.type === 'identifier' ? cur.text : cur.text?.replace(/^\$/, '') ?? null)
  }
  return null
}

/** Call names that neutralize taint (parameterizers, escapers, validators). */
const SANITIZER_METHODS = new Set([
  // parameterization / prepared statements
  'escape', 'escapestring', 'quote', 'mysql_real_escape_string', 'real_escape_string',
  'parameterize', 'prepare', 'preparestatement',
  // encoding / escaping
  'htmlescape', 'escapehtml', 'encodeuricomponent', 'encodeuri', 'quotemeta', 'shlex_quote', 'quote_plus',
  // path
  'basename', 'normalize', 'resolve', 'realpath', 'abspath', 'safe_join',
  // validation / allow-list
  'validate', 'sanitize', 'clean', 'allowlist', 'whitelist', 'iselement',
  'isalnum', 'isnumeric', 'isdigit', 'parseint', 'parsefloat', 'tonumber', 'int', 'uuid',
])
const SANITIZER_FULLNAMES = new Set([
  'path.basename', 'path.normalize', 'path.resolve', 'os.path.basename', 'os.path.abspath',
  'shlex.quote', 'html.escape', 'urllib.parse.quote', 'werkzeug.utils.secure_filename',
  'secure_filename', 'number', 'boolean',
])

function isSanitizer(call: NCall): boolean {
  return SANITIZER_METHODS.has(call.method.toLowerCase()) || SANITIZER_FULLNAMES.has(call.fullName.toLowerCase())
}

// ---- expression taint evaluation ------------------------------------------

interface Env {
  lang: SastLanguage
  /** Names this function's signature bound — gates the ambiguous request roots. */
  scope: TaintScope
  taint: Map<string, Origins>
  /** Remaining node-visit budget for the current phase (fixpoint solve, then
   *  sink queries). Each evalOrigins visit accesses web-tree-sitter node
   *  properties (namedChildren, text) that allocate in the grow-only WASM heap;
   *  unbounded recursion over a JSX-heavy fixpoint churns hundreds of MB per
   *  file. When exhausted the phase degrades to no-taint for the rest of the
   *  function — a partial result that `exhausted` makes reportable. */
  budget: number
  /** True once any phase ran out of budget: taint results for this function
   *  may be incomplete, so absence of a finding must not be presented as a
   *  fully-analyzed file. */
  exhausted: boolean
}

// A normal function solves in well under this; it only bounds pathological
// JSX/expression fixpoints that would otherwise OOM the scan.
const TAINT_VISIT_BUDGET = 12_000

/** Origins that can flow out of an expression given the current taint map. */
function evalOrigins(node: SyntaxNode, env: Env, depth = 0): Origins {
  if (depth > 60) return []
  if (--env.budget < 0) {
    env.exhausted = true
    return []
  }
  const lang = env.lang
  const n = unwrap(node, lang)

  // 1. direct source? (raw node — sourceKindOf needs to see `await params`
  // before unwrap strips the await; it unwraps internally for everything else)
  const src = sourceKindOf(node, lang, env.scope)
  if (src) return [{ kind: 'source', sourceKind: src, node: n }]

  // 2. calls
  const call = asCall(n, lang)
  if (call) {
    if (isSanitizer(call)) return [] // sanitized → clean
    // NOTE: `new URL('<literal>', base)` deliberately does NOT propagate taint.
    // A compile-time-constant first argument fixes the target; the (often
    // tainted) second argument only supplies the absolute-URL base to resolve
    // against — the standard Next.js `NextResponse.redirect(new URL('/login',
    // req.url))` idiom, not an open redirect or SSRF. Trade-off: the rare
    // `new URL('/fixed', attackerControlledBase)` host injection is suppressed too.
    if (call.fullName.toLowerCase() === 'url' && stringLiteralValue(call.args[0], lang) !== null) return []
    // `new URLSearchParams({ … })` is a query-string BUILDER, and its
    // serialization is application/x-www-form-urlencoded: every character that
    // could carry structure — '/', ':', '<', '&', '=', '?', '#' — comes back
    // percent-encoded. A value put in this way can only ever emerge as an
    // encoded query VALUE, so it can reach neither an origin nor a markup
    // context. Gated on the object-literal argument form, which is the builder:
    // `new URLSearchParams(location.search)` PARSES instead, and reading a
    // value back out of it is the DOM-XSS shape, so that form keeps its taint.
    // Residual unsoundness: `.get()` on a builder returns the value decoded
    // again. That round trip is a no-op nobody writes.
    if (
      call.isConstruct &&
      call.fullName.toLowerCase() === 'urlsearchparams' &&
      call.args[0] &&
      unwrap(call.args[0], lang).type === 'object'
    ) {
      return []
    }
    let acc: Origins = []
    if (call.receiver) acc = mergeOrigins(acc, evalOrigins(call.receiver, env, depth + 1))
    for (const a of call.args) acc = mergeOrigins(acc, evalOrigins(a, env, depth + 1))
    return acc
  }

  // 3. string concatenation
  const parts = concatOperands(n, lang)
  if (parts) {
    let acc: Origins = []
    for (const p of parts) acc = mergeOrigins(acc, evalOrigins(p, env, depth + 1))
    return acc
  }

  // 4. string interpolation (template literals / f-strings / interpolated strings)
  const interp = interpolationExprs(n, lang)
  if (interp) {
    let acc: Origins = []
    for (const e of interp) acc = mergeOrigins(acc, evalOrigins(e, env, depth + 1))
    return acc
  }

  // 5. subscript / index — taint of the base container
  const sub = subscriptBase(n)
  if (sub) return evalOrigins(sub, env, depth + 1)

  // 6. member access — taint of the object
  const m = asMember(n, lang)
  if (m) return evalOrigins(m.object, env, depth + 1)

  // 7. bare identifier
  const id = identifierName(n, lang)
  if (id) return env.taint.get(id) ?? []

  // 8. fall back to a bounded union over subexpressions (ternary, casts, etc.)
  if (n.namedChildCount > 0 && n.namedChildCount <= 8) {
    let acc: Origins = []
    for (const c of n.namedChildren) acc = mergeOrigins(acc, evalOrigins(c, env, depth + 1))
    return acc
  }
  return []
}

// ---- function-level analysis ----------------------------------------------

/** Which param indexes of a function reach a sink (for the interprocedural hop). */
export interface FnSummary {
  name: string
  params: string[]
  /** param index → true if that param flows into any sink in this function. */
  sinkParams: Set<number>
}

export interface FunctionTaint {
  fn: NFunc
  /** Final taint map: variable → origins. */
  env: Env
  summary: FnSummary
}

/**
 * Run the fixpoint taint solver over one function body. Seeds params as taint
 * origins (for the interprocedural summary) and lets real sources seed
 * themselves through assignments.
 */
export function analyzeFunction(fn: NFunc, lang: SastLanguage): FunctionTaint {
  const taint = new Map<string, Origins>()
  // Lower-cased because every root lookup in sourceKindOf is lower-cased —
  // `searchParams` must still match the `searchparams` root.
  const paramNames = new Set(
    [...paramBoundNames(fn.node)].map((p) => p.toLowerCase()),
  )
  const env: Env = { lang, scope: { paramNames }, taint, budget: TAINT_VISIT_BUDGET, exhausted: false }

  // Seed parameters so we can learn which ones reach sinks.
  fn.params.forEach((p, i) => {
    if (p) taint.set(p, [{ kind: 'param', index: i, name: p, node: fn.node }])
  })

  const summary: FnSummary = { name: fn.name, params: fn.params, sinkParams: new Set() }
  if (!fn.body) return { fn, env, summary }

  const assigns = collectAssignments(fn.body, lang)
  // Fixpoint: propagate through assignments until stable (bounded).
  for (let iter = 0; iter < 8; iter++) {
    let changed = false
    for (const a of assigns) {
      const before = taint.get(a.target) ?? []
      const rhs = evalOrigins(a.value, env)
      if (rhs.length === 0) continue
      const merged = mergeOrigins(before, rhs)
      if (merged.length !== before.length) {
        taint.set(a.target, merged)
        changed = true
      }
    }
    if (!changed) break
  }
  // The solve and the later sink queries (taintOf) share this env. Give the
  // query phase its own fresh budget so a churn-heavy solve cannot silently
  // blind every subsequent sink check; `exhausted` keeps the drained solve
  // reportable as degraded coverage.
  env.budget = TAINT_VISIT_BUDGET
  return { fn, env, summary }
}

/** True if any taint phase for this function ran out of visit budget — its
 *  results may be incomplete and the file must be reported as truncated. */
export function taintBudgetExhausted(ft: FunctionTaint): boolean {
  return ft.env.exhausted
}

/** Origins reaching a specific expression, using a solved function environment. */
export function taintOf(node: SyntaxNode, ft: FunctionTaint): Origins {
  return evalOrigins(node, ft.env)
}

/** True if the given origins include a real (non-parameter) untrusted source. */
export function hasRealSource(origins: Origins): boolean {
  return origins.some((o) => o.kind === 'source')
}

/** Param indexes present in the origins (for interprocedural summaries). */
export function paramIndexes(origins: Origins): number[] {
  return origins.filter((o): o is Extract<Origin, { kind: 'param' }> => o.kind === 'param').map((o) => o.index)
}

/**
 * The single parameter an expression came from, when that is ALL it came from.
 *
 * Returns null the moment anything else is mixed in — a real source, a second
 * parameter — because the caller of this (the caller-supplied-argument report)
 * is making a claim about provenance, not about danger: "this value is exactly
 * what one caller passed". A merged value is not that.
 */
export function soleParamOrigin(origins: Origins): Extract<Origin, { kind: 'param' }> | null {
  if (origins.length !== 1) return null
  const only = origins[0]
  return only.kind === 'param' ? only : null
}

/** First real source origin, for flow reporting. */
export function firstSource(origins: Origins): Extract<Origin, { kind: 'source' }> | null {
  return origins.find((o): o is Extract<Origin, { kind: 'source' }> => o.kind === 'source') ?? null
}

/**
 * Whether a call site may bind to a same-file function summary.
 *
 * Interprocedural summaries are keyed by a function's last-segment name, so a
 * bare name collision — e.g. `logger.run(x)` at the call site vs. a local
 * `function run(cmd) { exec(cmd) }` — would otherwise resolve to the wrong
 * callee and mis-report a one-hop flow. A call binds to a local-function
 * summary only when it is a direct call (`run(x)`) or an in-object self call
 * (`this.run(x)` / `self.run(x)`); a member call on any other receiver is a
 * different function that merely shares a name, so it must not match.
 */
export function bindsToLocalFn(call: NCall): boolean {
  if (!call.receiver) return true
  const recv = call.receiverName?.toLowerCase()
  return recv === 'this' || recv === 'self'
}

export { walk }
