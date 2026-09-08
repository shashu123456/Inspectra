# Inspectra Security Assessment Report

**Target:** `http://127.0.0.1:33695`
**Date:** 2026-09-08 18:36:34 IST
**Tool:** inspectra 1.0.0
**Duration:** 0.6s

## Posture Score: 4.0 / 100 (F)

## Summary

| Severity | Count |
|----------|-------|
| High | 0 |
| Medium | 4 |
| Low | 4 |
| Info | 5 |
| **Total** | **13** |

## Findings

### [MEDIUM] HDR-001 — Missing security header: Strict-Transport-Security

- **Category:** security_headers
- **Confidence:** Medium
- **What was observed:** The Strict-Transport-Security response header was not present on 127.0.0.1.
- **Why it matters:** HSTS tells browsers to only connect over HTTPS for a set period, protecting users from protocol-downgrade and cookie-hijacking attacks.
- **Recommendation:** Set Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response.
- **Evidence:**
  - `Header not present in the HTTP response`

### [MEDIUM] HDR-002 — Missing security header: Content-Security-Policy

- **Category:** security_headers
- **Confidence:** Medium
- **What was observed:** The Content-Security-Policy response header was not present on 127.0.0.1.
- **Why it matters:** CSP restricts which resources a page may load, sharply reducing the impact of cross-site scripting (XSS) and injection attacks.
- **Recommendation:** Add a Content-Security-Policy header with explicit source allowlists (start with default-src 'self' and tighten over time).
- **Evidence:**
  - `Header not present in the HTTP response`

### [MEDIUM] HDR-003 — Missing security header: X-Frame-Options

- **Category:** security_headers
- **Confidence:** Medium
- **What was observed:** The X-Frame-Options response header was not present on 127.0.0.1.
- **Why it matters:** Without clickjacking protection an attacker can embed the page in a transparent iframe and trick users into unintended actions.
- **Recommendation:** Set X-Frame-Options: DENY (or SAMEORIGIN if framing by same-origin pages is required).
- **Evidence:**
  - `Header not present in the HTTP response`

### [MEDIUM] TLS-001 — HTTPS not available

- **Category:** tls
- **Confidence:** High
- **What was observed:** Could not establish a TLS connection to 127.0.0.1:33695: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1006)
- **Why it matters:** Without HTTPS, all traffic — including credentials — is transmitted in plaintext.
- **Recommendation:** Enable TLS on the server and redirect HTTP traffic to HTTPS.
- **Evidence:**
  - `TLS handshake to 127.0.0.1:33695 failed`

### [LOW] HDR-004 — Missing security header: X-Content-Type-Options

- **Category:** security_headers
- **Confidence:** Medium
- **What was observed:** The X-Content-Type-Options response header was not present on 127.0.0.1.
- **Why it matters:** Without nosniff, browsers may guess the MIME type of a response, which can turn an upload into an executable script.
- **Recommendation:** Set X-Content-Type-Options: nosniff on all responses.
- **Evidence:**
  - `Header not present in the HTTP response`

### [LOW] HDR-005 — Missing security header: Referrer-Policy

- **Category:** security_headers
- **Confidence:** Medium
- **What was observed:** The Referrer-Policy response header was not present on 127.0.0.1.
- **Why it matters:** Referrer-Policy controls how much of the previous URL is leaked to other sites, protecting sensitive query strings and paths.
- **Recommendation:** Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for highly sensitive applications).
- **Evidence:**
  - `Header not present in the HTTP response`

### [LOW] HDR-006 — Missing security header: Permissions-Policy

- **Category:** security_headers
- **Confidence:** Medium
- **What was observed:** The Permissions-Policy response header was not present on 127.0.0.1.
- **Why it matters:** Permissions-Policy restricts which browser features (camera, microphone, geolocation) a page and its frames may use.
- **Recommendation:** Set Permissions-Policy with a restrictive default, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=().
- **Evidence:**
  - `Header not present in the HTTP response`

### [LOW] HDR-007 — Missing security header: Cross-Origin-Resource-Policy

- **Category:** security_headers
- **Confidence:** Medium
- **What was observed:** The Cross-Origin-Resource-Policy response header was not present on 127.0.0.1.
- **Why it matters:** CORP stops other origins from loading this site's resources, reducing cross-origin data leakage.
- **Recommendation:** Set Cross-Origin-Resource-Policy: same-origin unless cross-origin embedding is explicitly required.
- **Evidence:**
  - `Header not present in the HTTP response`

### [INFO] FPR-001 — Technologies identified

- **Category:** fingerprinting
- **Confidence:** Medium
- **What was observed:** Identified the following technologies on 127.0.0.1: Nginx 1.24.0, PHP 7.4.3.
- **Why it matters:** Known technologies help prioritize patching and reveal the stack an attacker would study first.
- **Recommendation:** Keep all identified components patched and disable version disclosure where possible.
- **Evidence:**
  - `Server: Werkzeug/3.1.8 Python/3.11.9, nginx/1.24.0`
  - `X-Powered-By: PHP/7.4.3`

### [INFO] HDR-008 — Header should be removed: X-Powered-By

- **Category:** security_headers
- **Confidence:** High
- **What was observed:** The X-Powered-By header is present on 127.0.0.1.
- **Why it matters:** The X-Powered-By header reveals the framework and often its version, giving attackers a head start on known vulnerabilities.
- **Recommendation:** Remove the 'X-Powered-By' response header (or disable the framework option that adds it) to reduce information disclosure.
- **Evidence:**
  - `X-Powered-By: PHP/7.4.3`

### [INFO] HTP-003 — Web server software disclosed (with version)

- **Category:** http
- **Confidence:** High
- **What was observed:** The server disclosed its software via the Server header: 'Werkzeug/3.1.8 Python/3.11.9, nginx/1.24.0'.
- **Why it matters:** Version numbers help attackers identify known vulnerabilities. Even without a version, the software name narrows the attack surface.
- **Recommendation:** Remove the 'Server' response header (or disable the framework option that adds it) to reduce information disclosure.
- **Evidence:**
  - `Server: Werkzeug/3.1.8 Python/3.11.9, nginx/1.24.0`

### [INFO] ROB-002 — robots.txt disallows crawler access to paths

- **Category:** robots
- **Confidence:** High
- **What was observed:** robots.txt disallows 2 path(s) from crawlers.
- **Why it matters:** Disallowed paths are excluded from search engines, not from attackers. Anything listed here should be reviewed for exposure.
- **Recommendation:** Review the disallowed paths: sensitive content should be protected by authentication, not just robots.txt.
- **Evidence:**
  - `/admin`
  - `/private`

### [INFO] ROB-003 — Sitemap referenced in robots.txt

- **Category:** robots
- **Confidence:** High
- **What was observed:** robots.txt references 1 sitemap location(s).
- **Why it matters:** Sitemaps expose the site structure to crawlers (and to anyone reading robots.txt).
- **Recommendation:** Confirm the sitemap does not list sensitive or unpublished URLs.
- **Evidence:**
  - `https://example.com/sitemap.xml`

---

_This report was generated by Inspectra, a passive security assessment tool. Inspectra never exploits: it observes, assesses, explains and reports. Only scan systems you own or are authorized to test._
