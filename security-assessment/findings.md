## 1. Reflected/DOM XSS in Product Search — OWASP A03: Injection / CWE-79

**Vulnerability:** The product search feature reflected the user-supplied
`q` query parameter back into the page as trusted HTML, allowing arbitrary
script execution in the victim's browser.

**Exploit:** Entering the payload `<iframe src="javascript:alert(\`xss\`)">`
into the search field produced an executing `alert('xss')` dialog. Because
the payload persists in the URL (`/#/search?q=...`), the attack is
weaponizable as a link: any authenticated user who opens it runs the
attacker's script in their own session.

**Root cause:** In `frontend/src/app/search-result/search-result.component.ts`,
`filterTable()` assigned the search term via
`this.sanitizer.bypassSecurityTrustHtml(queryParam)`. Angular sanitizes
interpolated values by default; `bypassSecurityTrustHtml` explicitly disables
that protection, so the raw `<iframe>` markup was rendered as live DOM.
(A second instance of the same anti-pattern exists in
`trustProductDescription()` for product descriptions — same root cause,
different sink.)

**Fix:** Replaced the bypass with Angular's sanitizer in enforcing mode:
`this.sanitizer.sanitize(SecurityContext.HTML, queryParam) ?? ''`. This
strips dangerous markup (script, iframe, event handlers) instead of trusting
it, while leaving benign search text intact.

**Verification:** Rebuilt the frontend and replayed the identical payload
after a hard refresh. The `<iframe>` string now renders as inert text with
no dialog — script execution is blocked. (Evidence: 01-xss-exploit.png,
01-xss-fixed.png)

**Design note (CRM hook):** In my own CRM build, user-supplied fields were
bound through the framework's default escaping rather than any trust-bypass
API — this finding is a concrete example of the class of bug that choice
prevents at build time.

## 2. SQL Injection in Login — OWASP A03: Injection / CWE-89

**Vulnerability:** The login endpoint built its authentication SQL query by
concatenating the user-supplied email directly into the query string,
allowing an attacker to alter the query's logic and bypass authentication.

**Exploit:** Submitting email `' OR 1=1--` with any password logged the
attacker in as the administrator (`admin@juice-sh.op`). The injected
`' OR 1=1` makes the WHERE clause always true and `--` comments out the
password check, so the query returns all users and the app authenticates as
the first row. The resulting admin JWT then enabled a full dump of the user
table via `GET /api/Users` — turning an auth bypass into data exfiltration.

**Root cause:** In `routes/login.ts`, the query was assembled as a template
literal: `SELECT * FROM Users WHERE email = '${req.body.email}' AND
password = '${security.hash(req.body.password)}'`. User input was treated as
executable SQL rather than data.

**Fix:** Rewrote the query to use Sequelize bound parameters (`$email`,
`$password`) supplied via the `bind` option. The query structure is now fixed
at author-time; user input can only occupy value slots, so injection
metacharacters are treated as a literal (non-matching) email.

**Verification:** Rebuilt the backend and replayed `' OR 1=1--` after logging
out and hard-refreshing — login is now rejected with "Invalid email or
password," while legitimate credentials still authenticate normally.
(Evidence: 02-sqli-exploit.png, 02-sqli-exfil.png, 02-sqli-fixed.png)

**Design note (CRM hook):** The auth layer I built for my CRM used the ORM's
parameterized query interface by default rather than string-built SQL — this
finding is the exploit that choice is designed to prevent.


## 7. Weak Password Hashing — OWASP A02: Cryptographic Failures / CWE-327

**Vulnerability:** User passwords are hashed with unsalted MD5, a fast and
cryptographically broken algorithm unsuitable for password storage.

**Evidence:** In `routes/login.ts` the password is processed via
`security.hash(req.body.password)`; that helper (in `lib/insecurity.ts`) uses
`crypto.createHash('md5')` with no salt. Identical passwords therefore produce
identical hashes, and the full keyspace is trivially crackable with rainbow
tables. (Found by source review rather than the API, as this version strips
the `password` field from `/api/Users` responses.)

**Root cause:** Use of a general-purpose fast hash (MD5) instead of a
purpose-built, salted, computationally expensive password hashing function.

**Fix (design-level):** Replace with bcrypt/scrypt/Argon2, which apply a
per-user salt and tunable work factor. Not patched here because the seeded
accounts and several app flows depend on the existing hash scheme; documented
as a design finding with the recommended remediation.

**Design note (CRM hook):** Account passwords in my CRM were never stored with
a reversible or fast hash — a salted adaptive hash is the baseline this finding
highlights.

## 3. Insecure Direct Object Reference (IDOR) on Basket — OWASP A01: Broken Access Control / CWE-639

**Vulnerability:** The basket retrieval endpoint returned any basket by its
numeric ID without verifying the basket belonged to the authenticated user,
allowing a logged-in user to read other users' basket contents.

**Exploit:** Logged in as a normal user (`test@test.local`, own basket ID 6),
a direct request to `GET /rest/basket/1` — authenticated with the user's own
JWT — returned the administrator's basket in full, including its `UserId: 1`
and all line items. Iterating the ID enumerates every user's basket.

**Root cause:** In `routes/basket.ts`, `retrieveBasket()` queried
`BasketModel.findOne({ where: { id } })` using only the client-supplied `:id`
parameter. The handler even computed the caller's own basket ID (`user.bid`)
for an unrelated purpose but never used it to authorize the request — the
object reference was trusted directly, with no ownership check.

**Fix:** Added an ownership guard before the query: the caller's identity is
read from the verified session (`security.authenticatedUsers.from(req)`), and
the request is rejected with HTTP 401 unless the session's `bid` matches the
requested `:id`. Authorization is now derived from the server-trusted token,
never from client-controlled input.

**Verification:** After rebuilding the backend, `GET /rest/basket/1` returns
`401 { "error": "Unauthorized access to basket" }`, while the user's own
`GET /rest/basket/6` still succeeds — the fix blocks cross-user access
without affecting legitimate access. (Evidence: 03-idor-exploit.png,
03-idor-fixed.png)

**Design note (CRM hook):** This is the exact class of bug that multi-tenant
access control is built to prevent. In my CRM, every record fetch was scoped
to the owning user/organisation server-side rather than trusting the ID in the
request — object-level authorization enforced at the query, which is precisely
the control missing here.

## 4. Broken Access Control on Admin User-Details API — OWASP A01 / CWE-284 (Improper / Missing Authorization)

**Vulnerability:** The `/rest/user/authentication-details` endpoint, which
returns every user's account details, was guarded only by a check that the
caller was logged in — not that they held the admin role. Any authenticated
user could retrieve the full user list.

**Exploit:** While the admin UI (`/#/administration`) correctly returned a 403
to a normal customer, the underlying API did not. Logged in as a customer
(`test@test.local`), a direct `GET /rest/user/authentication-details` with the
customer's own JWT returned the complete user table — IDs, emails, roles and
`totpSecret` fields. The client-side route guard gave a false impression of
protection the API never enforced.

**Root cause:** In `server.ts`, the route was protected with
`security.isAuthorized()` (valid-session check) instead of a role check. The
codebase had no admin-level guard — only `isAuthorized`, `isAccounting`,
`isDeluxe` and `isCustomer` in `lib/insecurity.ts`.

**Fix:** Added an `isAdmin()` guard to `lib/insecurity.ts`, mirroring the
existing `isAccounting()` pattern but matching `roles.admin`, returning 403
otherwise. Changed the route registration to
`app.use('/rest/user/authentication-details', security.isAdmin())`.

**Verification:** After rebuilding, the same customer request returns
`403 { "error": "Requires admin privileges" }`; an admin session still
retrieves the data. (Evidence: 04-adminapi-exploit.png, 04-adminapi-fixed.png)

**Design note (CRM hook):** This is vertical privilege enforcement — the
difference between "authenticated" and "authorized for this role." My CRM's
SSO/role layer gated privileged endpoints on role server-side, never relying
on the UI to hide them, which is precisely the control that was missing here.

## 5. Missing Server-Side Password Policy — OWASP A07: Identification & Authentication Failures / CWE-521

**Vulnerability:** User registration enforced no meaningful password strength
on the server. The client hinted only at a 5–40 character length, and the API
accepted trivially weak passwords, leaving accounts open to brute-force and
credential-stuffing attacks.

**Exploit:** Registering via `POST /api/Users` with a 3-character numeric
password (`123`) succeeded and created a usable account — no length,
complexity, or common-password check was applied server-side.

**Root cause:** The registration chain in `server.ts` validated only that the
email/password were non-empty and matched the repeat field. No password-policy
middleware existed, and the only strength guidance (5-char minimum) lived in
the client, which an attacker bypasses by calling the API directly.

**Fix:** Added a server-side password-policy middleware to the `POST /api/Users`
chain: minimum 8 characters, requiring both letters and numbers, and rejecting
a small common-password denylist, returning HTTP 400 otherwise. Validation now
runs on the server, before user creation.

**Verification:** After rebuilding, registration with a weak password returns
`400 Bad Request`, while a strong password (`Portfolio2026`) registers and
authenticates normally. (Evidence: 05-weakpass-exploit.png, 05-weakpass-fixed.png)

**Design note / modern standard:** The implemented rule is a pragmatic baseline.
Current NIST guidance (SP 800-63B) de-emphasises composition rules in favour of
longer minimum length and screening new passwords against known-breached lists
(e.g. the HaveIBeenPwned range API). The finding recommends that approach for a
production system. In my CRM, auth policy was enforced server-side at the
account layer rather than trusted to the client — the control this finding adds.

## 6. Verbose Error Handling / Information Disclosure — OWASP A05: Security Misconfiguration / CWE-209

**Vulnerability:** The application returns unhandled errors with internal
detail (stack traces, library and query information) rather than a generic,
consistent error response, leaking implementation details useful to an attacker.

**Exploit:** Supplying malformed input to an endpoint — e.g. a non-numeric
basket ID at `GET /rest/basket/xyz` — triggers an unhandled exception whose
response exposes internal error detail instead of a clean, generic message.

**Root cause:** Errors propagate to a default handler that echoes internal
diagnostics in the response body, with no uniform error-shaping layer to
sanitise what clients see.

**Fix (design-level):** Introduce a centralised error handler that logs full
detail server-side but returns only a generic message and status code to the
client, applied consistently across all routes. Not patched here as it spans
the whole app and is a cross-cutting configuration concern rather than a single
vulnerable line.

**Design note (CRM hook):** Production error handling in my CRM distinguished
server-side logging from client-facing messages — detailed logs for debugging,
generic responses for users — which is the control this finding recommends.

## Scope & Honest Limitations

This project prioritised depth over breadth: rather than solving the full
OWASP Top 10 at surface level, I took six vulnerabilities across five
categories and carried each through the complete cycle — exploit, root-cause
analysis in source, a code-level fix, and verification that the fix closes the
hole without breaking legitimate functionality.

**Not covered, and why:**
- **A04 Insecure Design, A08 Software & Data Integrity, A10 SSRF** — not
  attempted; each needs scenario depth I chose to invest in the categories
  closest to my application-security background instead.
- **A06 Vulnerable Components** — Juice Shop ships deliberately outdated
  dependencies; I left these untouched by design (they are the lab's point)
  rather than treating dependency-bumping as a finding.
- **Findings #6 and #7** are documented with design-level remediation rather
  than patched: error handling is cross-cutting across all routes, and the MD5
  scheme is depended on by seeded accounts and multiple flows. In a real
  codebase both are straightforward; in this lab, fixing them in place would
  break unrelated functionality without adding to the lesson.

**Testing boundaries:** All testing was manual (browser, DevTools, direct API
calls) against a local instance. I did not use automated scanners (Burp/ZAP
active scans), fuzzing, or authenticated session-fixation testing — the goal
was to understand and fix each class by hand, not maximise finding count.