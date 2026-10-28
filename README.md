# OWASP Juice Shop — Exploit & Fix: An Application Security Assessment

A hands-on application security assessment of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).
For each vulnerability I **exploited it, traced the root cause in source, fixed it in code, and verified the fix closed the hole** without breaking legitimate functionality — the full defensive loop, not just a capture-the-flag run.

> **Background:** I built and secured a full-stack CRM (frontend, backend, auth, SSO) single-handedly. This project is the attack-side mirror of that work — each finding includes a design note linking the flaw back to how I'd prevent it at build time.

## Findings Summary

| # | Finding | OWASP (2021) | CWE | Severity | Status |
|---|---------|-------------|-----|----------|--------|
| 1 | DOM/Reflected XSS in search | A03 Injection | CWE-79 | High | Fixed in code ✓ |
| 2 | SQL injection in login | A03 Injection | CWE-89 | Critical | Fixed in code ✓ |
| 3 | IDOR on basket retrieval | A01 Broken Access Control | CWE-639 | High | Fixed in code ✓ |
| 4 | Missing authorization on user-details API | A01 Broken Access Control | CWE-284 | High | Fixed in code ✓ |
| 5 | No server-side password policy | A07 Auth Failures | CWE-521 | Medium | Fixed in code ✓ |
| 6 | Verbose error / version disclosure | A05 Security Misconfiguration | CWE-209 | Low | Documented (design fix) |
| 7 | Unsalted MD5 password hashing | A02 Cryptographic Failures | CWE-327 | High | Documented (design fix) |

**5 vulnerabilities fixed in code across 5 OWASP Top 10 categories; 2 documented with design-level remediation.**

## What's in this repo

- **[`security-assessment/findings.md`](security-assessment/findings.md)** — the full report: each finding as vulnerability → exploit → root cause → fix → verification, with a CRM design note and honest scope/limitations.
- **[`security-assessment/screenshots/`](security-assessment/screenshots/)** — exploit and post-fix evidence for each finding.
- **The code fixes themselves** — committed to this repo, one commit per finding (see the commit history). Key files: `routes/login.ts`, `routes/basket.ts`, `lib/insecurity.ts`, `server.ts`, `frontend/src/app/search-result/search-result.component.ts`.

## Method

All testing was manual — browser, DevTools, and direct API calls against a local instance run from source. I ran Juice Shop from source (rather than the Docker image) specifically so I could patch the actual code and prove each fix by rebuild-and-retest. Fixes extend the application's own patterns (e.g. an `isAdmin` guard mirroring the existing `isAccounting`) rather than bolting on foreign code.

See [`security-assessment/findings.md`](security-assessment/findings.md) for the complete write-up.

---
*Assessment by Aditi Nagpure. Juice Shop is © the OWASP Juice Shop contributors (MIT).*