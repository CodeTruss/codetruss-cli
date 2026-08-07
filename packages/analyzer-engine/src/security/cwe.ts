/**
 * CWE → OWASP Top-10 (2021) mapping and canonical titles for the classes this
 * engine detects. Keeping this in one table means every rule cites the same,
 * accurate identifiers — credibility depends on getting these exactly right.
 */

export interface CweInfo {
  cwe: string
  owasp: string
  title: string
}

export const CWE: Record<string, CweInfo> = {
  SQLI: { cwe: 'CWE-89', owasp: 'A03:2021 Injection', title: 'SQL Injection' },
  CMDI: { cwe: 'CWE-78', owasp: 'A03:2021 Injection', title: 'OS Command Injection' },
  CODEI: { cwe: 'CWE-95', owasp: 'A03:2021 Injection', title: 'Code Injection (eval)' },
  PATH: { cwe: 'CWE-22', owasp: 'A01:2021 Broken Access Control', title: 'Path Traversal' },
  SSRF: { cwe: 'CWE-918', owasp: 'A10:2021 Server-Side Request Forgery', title: 'Server-Side Request Forgery' },
  DESER: { cwe: 'CWE-502', owasp: 'A08:2021 Software and Data Integrity Failures', title: 'Insecure Deserialization' },
  ALLOC: { cwe: 'CWE-789', owasp: 'A08:2021 Software and Data Integrity Failures', title: 'Uncontrolled Memory Allocation' },
  DECOMP: { cwe: 'CWE-409', owasp: 'A08:2021 Software and Data Integrity Failures', title: 'Decompression Bomb (Data Amplification)' },
  WEAKHASH: { cwe: 'CWE-328', owasp: 'A02:2021 Cryptographic Failures', title: 'Weak Hash' },
  WEAKCIPHER: { cwe: 'CWE-327', owasp: 'A02:2021 Cryptographic Failures', title: 'Broken/Weak Cryptographic Algorithm' },
  WEAKRNG: { cwe: 'CWE-338', owasp: 'A02:2021 Cryptographic Failures', title: 'Cryptographically Weak PRNG' },
  TLS: { cwe: 'CWE-295', owasp: 'A07:2021 Identification and Authentication Failures', title: 'Improper Certificate Validation' },
  HARDCRED: { cwe: 'CWE-798', owasp: 'A07:2021 Identification and Authentication Failures', title: 'Hard-coded Credentials' },
  CLIENTSECRET: { cwe: 'CWE-200', owasp: 'A01:2021 Broken Access Control', title: 'Exposure of Sensitive Information' },
  XSS: { cwe: 'CWE-79', owasp: 'A03:2021 Injection', title: 'Cross-Site Scripting' },
  XXE: { cwe: 'CWE-611', owasp: 'A05:2021 Security Misconfiguration', title: 'XML External Entity (XXE)' },
  OPENREDIR: { cwe: 'CWE-601', owasp: 'A01:2021 Broken Access Control', title: 'Open Redirect' },
  COOKIE: { cwe: 'CWE-1004', owasp: 'A05:2021 Security Misconfiguration', title: 'Insecure Cookie' },
  REDOS: { cwe: 'CWE-1333', owasp: 'A05:2021 Security Misconfiguration', title: 'Regular Expression Denial of Service' },
  TIMING: { cwe: 'CWE-208', owasp: 'A02:2021 Cryptographic Failures', title: 'Observable Timing Discrepancy' },
  // CWE-252/362/697/1050 have no official OWASP Top-10 (2021) mapping — say so
  // rather than borrow an injection bucket the finding does not belong to.
  UNAWAITED: { cwe: 'CWE-252', owasp: 'Not mapped — reliability', title: 'Unchecked Return Value (floating promise)' },
  SWALLOW: { cwe: 'CWE-1069', owasp: 'A09:2021 Security Logging and Monitoring Failures', title: 'Empty Exception Block' },
  LOOSEEQ: { cwe: 'CWE-697', owasp: 'Not mapped — correctness', title: 'Incorrect Comparison' },
  NPLUSONE: { cwe: 'CWE-1050', owasp: 'Not mapped — performance', title: 'Excessive Platform Resource Consumption within a Loop' },
  MASSASSIGN: { cwe: 'CWE-915', owasp: 'A08:2021 Software and Data Integrity Failures', title: 'Mass Assignment' },
  RMWRACE: { cwe: 'CWE-362', owasp: 'Not mapped — correctness', title: 'Race Condition (lost update)' },
}
