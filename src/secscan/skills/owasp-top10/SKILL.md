---
name: owasp-top10
description: OWASP Top 10:2025 review checklist for a read-only whole-repository audit — per category, what to grep for, what evidence a finding needs, and how it maps onto secscan's critical/high rubric and CWE categories. Use for web services, APIs and anything with an authenticated surface.
license: MIT
metadata:
  standards: OWASP Top 10:2025, ASVS 5.0 (selected), CWE
  see-also: https://github.com/agamm/claude-code-owasp (broader reference, MIT)
---

# OWASP Top 10:2025 — read-only review checklist

Work the categories in the order below; the first four hold most High/Critical
findings. For each one, the *Locate* line tells you what to `Grep`/`Glob` for,
*Evidence* is the minimum you must have read before reporting, and *Severity*
maps the category onto the rubric in the base prompt. Use the CWE in the finding's
`category` field.

## A01 Broken access control

- Locate: route/handler registrations; decorators and middleware such as
  `@login_required`, `@PreAuthorize`, `[Authorize]`, `auth.middleware`,
  `before_action`, `can?`, `policy`, `permission_classes`; object lookups by an
  id taken from the request (`params[:id]`, `req.params.id`, `request.args`,
  `@PathVariable`); admin/internal prefixes; CORS configuration; multi-tenant
  filters (`tenant_id`, `org_id`, `owner ==`).
- Evidence: an endpoint that mutates or reads another principal's data where the
  handler and every middleware on its path fail to check ownership/role
  (CWE-639 IDOR, CWE-862 missing authz, CWE-863 incorrect authz), or a
  CORS policy that reflects any origin **with** credentials (CWE-942).
- Severity: `critical` when an unauthenticated caller reaches admin or
  cross-tenant data/actions; `high` for authenticated horizontal/vertical
  escalation. Missing checks on read-only public data are not findings.

## A02 Security misconfiguration

- Locate: `DEBUG = True`, `app.debug`, `spring.devtools`, `NODE_ENV`, default
  admin accounts, `0.0.0.0` binds combined with no auth, permissive
  `ALLOWED_HOSTS = ['*']`, XML parsers (`resolve_entities`, `XMLInputFactory`,
  `DocumentBuilderFactory`, `lxml`), directory listing, `verify=False`,
  `InsecureSkipVerify`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED`,
  `TrustAllCerts`, `ssl_verify false`, Dockerfiles/compose, IaC.
- Evidence: the setting is effective in a shipped configuration (not only under
  a `dev`/`test` profile) and the consequence is concrete: XXE with untrusted XML
  (CWE-611), disabled TLS verification on a connection carrying credentials or
  authorization decisions (CWE-295), debug endpoints exposing secrets or code
  execution (CWE-489).
- Severity: `high` for XXE on untrusted input and for TLS verification disabled
  on a credential-bearing connection; `critical` for a debug console/RCE
  endpoint reachable without auth. Plain hardening gaps are `low`.

## A03 Software supply chain failures

- Locate: dependency manifests and lockfiles; install hooks (`postinstall`,
  `setup.py` `cmdclass`, `build.gradle` `exec`); `curl | sh` in build scripts;
  unpinned `FROM image:latest`; GitHub Actions referenced by mutable tag with
  `secrets` or `write` permissions; git dependencies by branch.
- Evidence: without a vulnerability database you cannot confirm a CVE. Report
  a dependency only when the repository itself calls a known-vulnerable API in
  the vulnerable way and you are confident of the advisory, or when the build
  executes remote code that an attacker can change (CWE-829, CWE-494).
- Severity: `high` for build steps that execute unpinned remote content with
  access to secrets; otherwise `low`/`info` and leave the rest to a dependency
  scanner.

## A04 Cryptographic failures

- Locate: `md5`, `sha1` for passwords/signatures, `DES`, `RC4`, `ECB`,
  `Random`/`Math.random`/`rand()` for tokens, hardcoded IV/salt/key, `AES` with
  static key in source, JWT `alg: none` or `verify=False`/`decode(..., verify=False)`,
  `jwt.decode` without algorithms list, `SECRET_KEY =`, password storage via
  plain hash instead of bcrypt/scrypt/argon2, homemade crypto.
- Evidence: the weak primitive protects something that matters (passwords,
  session/API tokens, signatures that gate authorization, PII at rest) and the
  weakness is reachable: e.g. a JWT accepted without signature verification
  (CWE-347), a token generated from a non-CSPRNG (CWE-338), passwords stored
  with unsalted fast hashes (CWE-916), a symmetric key hardcoded in the repo
  (CWE-321).
- Severity: `critical` for signature bypass that yields authentication bypass;
  `high` for the rest above. TLS 1.1 allowed or a deprecated cipher order in a
  config is `low`.

## A05 Injection

- Locate: string-built SQL (`f"SELECT`, `"... " + `, `format(`, `%s` into
  `execute`, `raw(`, `text(`, `createNativeQuery`, `$where`, `$regex` with input),
  shell (`os.system`, `subprocess(..., shell=True)`, `exec`, `child_process.exec`,
  `Runtime.exec`, backticks, `popen`), template engines with attacker-controlled
  *templates* (`render_template_string`, `Template(user_input)`, `new Function`),
  LDAP/XPath filters, `eval`, deserializers (`pickle.loads`, `yaml.load` without
  `SafeLoader`, `ObjectInputStream`, `unserialize`, `Marshal.load`,
  `BinaryFormatter`), path building (`os.path.join(base, user)`, `open(`,
  `sendFile`, `../`), HTML sinks (`innerHTML`, `dangerouslySetInnerHTML`,
  `|safe`, `Markup`, `html.raw`), header/redirect sinks.
- Evidence: the full source → sink path with no effective parameterization,
  allowlist, or escaping. Name the CWE: 89 SQL, 78 OS command, 94 code, 502
  deserialization, 22 path traversal, 79 XSS, 90 LDAP, 1336 template, 601 open
  redirect.
- Severity: `critical` for unauthenticated RCE/deserialization or SQLi giving
  full data access; `high` for authenticated injection, path traversal that
  reads outside the intended directory, stored XSS that reaches other users.
  Reflected XSS with limited impact and open redirects are `medium`.

## A06 Insecure design

- Locate: password reset and invitation flows, OTP/2FA verification, "remember
  me", account enumeration, business-logic limits (quantity, price, balance),
  trust boundaries between services, feature flags that disable security.
- Evidence: a logic flaw an attacker can drive end-to-end from the code:
  reset token accepted for any user, OTP compared without binding to the
  session, price taken from the client (CWE-840, CWE-640).
- Severity: `critical`/`high` when it yields account takeover or money; skip
  vague "no threat model" observations.

## A07 Authentication failures

- Locate: login handlers, session creation/rotation, cookie flags for the
  session cookie, JWT issuing/validation, API-key checks (`==` on secrets — note
  but do not over-rank timing), password policy, brute-force guards, "test"
  backdoors (`if password == "letmein"`, `X-Debug-Auth` headers), default
  credentials in config.
- Evidence: bypass or takeover path: authentication skipped for a route family,
  a hardcoded backdoor credential, session fixation with attacker-settable id,
  a JWT trusted from the client without verification (CWE-287, CWE-798,
  CWE-384).
- Severity: `critical` for unauthenticated bypass or backdoor; `high` for
  fixation/takeover requiring interaction. Missing MFA and weak password rules
  are `low`.

## A08 Software or data integrity failures

- Locate: auto-update code, plugin loaders, `pickle`/`yaml`/`marshal` of data
  from the network or DB, signature checks that are optional or ignored,
  webhooks without signature verification (`X-Hub-Signature`, `Stripe-Signature`),
  CI workflows (see the `cicd-and-iac` skill for the detailed checklist).
- Evidence: untrusted data deserialized or executed as code, or an integrity
  check that can be skipped (CWE-502, CWE-345, CWE-494).
- Severity: `critical` for unauthenticated deserialization to RCE; `high` for a
  webhook that mutates state without signature verification.

## A09 Logging and alerting failures

- Locate: loggers writing request bodies, headers (`Authorization`, `Cookie`),
  passwords, tokens, card numbers, full SSNs; audit logs missing on security
  events.
- Evidence: a secret or credential reaches a log line (CWE-532). Missing audit
  logging alone is not reportable.
- Severity: `high` for credentials/tokens in logs; `medium` for PII.

## A10 Mishandling of exceptional conditions

- Locate: `except: pass` around authentication/authorization, fail-open
  defaults (`allow = True` before a check that may throw), error handlers that
  grant access or return cached privileged data, missing `finally` releasing a
  lock that guards a security decision.
- Evidence: an error path that leaves the caller *more* privileged than the
  success path (CWE-636, CWE-703 with security consequence).
- Severity: `high` when the fail-open bypasses authentication/authorization;
  otherwise `low`.

## SSRF (still a first-class check)

Locate `requests.get(url)`, `fetch(url)`, `http.Get`, `URL(...).openStream`,
`HttpClient`, image/PDF fetchers, webhook testers, "import from URL" features,
where `url` derives from input. Evidence: the host is attacker-controlled (not
just the path) and there is no allowlist; internal metadata endpoints
(`169.254.169.254`, `metadata.google.internal`) or internal services are
reachable (CWE-918). Severity: `high`; `critical` if the response is returned to
the attacker and cloud credentials are reachable.

## Output discipline

- `category`: `CWE-###: Name` (add the OWASP letter in the description if useful).
- `file_path` relative to the repository root, `line_range` of the sink.
- Describe source, path and sink in the `description`; put the fix in
  `recommendation` (parameterize, allowlist, verify signature, use CSPRNG…).
