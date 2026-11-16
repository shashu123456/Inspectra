# Inspectra Threat Model

Inspectra is a **passive, authorized security assessment CLI**. It observes
what a target willingly exposes over HTTP/TLS/DNS and reports configuration
weaknesses. It does **not** exploit, brute-force, or deliver payloads. This
threat model documents what Inspectra defends against, what it does not, and
where each mitigation lives in the code.

## 1. Scope and non-goals

**In scope:**
- Passive scanning of targets the operator is authorized to assess.
- Integrity and authenticity of scan evidence (findings, `evidence_hash`).
- Redaction of secrets before any report is serialized.
- Prevention of SSRF and DNS-rebinding abuse of the scanner itself.

**Non-goals (explicitly out of scope):**
- Exploitation, payload delivery, or post-exploitation.
- Authentication bypass or credential cracking.
- Vulnerability chaining or active attack simulation.
- Fuzzing of unauthenticated input surfaces.
- Any scanning performed without explicit target consent.

Inspectra is a defensive assessment tool. The check registry and
contribution policy enforce "observe, assess, explain, report — never
exploit" (`CHANGELOG.md`, Security section).

## 2. Assets

- **Scan targets** — hostnames/IPs and URLs submitted for assessment.
- **Report integrity** — JSON/Markdown/HTML/SARIF output and `evidence_hash`
  values that reviewers rely on.
- **Operator identity** — the consent/authorization decision recorded for a
  scan (`--authorized`, consent banner in `src/inspectra/cli.py`).
- **Evidence files** — fixtures, saved baselines, and generated reports.

## 3. Threats and mitigations

### SSRF to internal networks

**Threat:** An attacker controls (or influences) a target URL and causes
Inspectra to issue requests to internal/private addresses
(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback, link-local,
CGNAT 100.64.0.0/10, unique-local, metadata endpoints), leaking internal
metadata or scanning internal hosts.

**Mitigation:**
- Target hostnames/IPs are validated before any network I/O
  (`src/inspectra/safety.py`).
- Blocked network list includes private/loopback/link-local/CGNAT,
  unique-local, unspecified, multicast, and metadata endpoints
  (`src/inspectra/safety.py`: `METADATA_ENDPOINTS`, `BLOCKED_NETWORKS`).
- Access to blocked networks is denied unless explicitly allowed via
  `--allow-private` together with `--authorized`
  (`src/inspectra/cli.py`, `src/inspectra/safety.py`).

**Residual risk:** A misconfigured `--allow-private --authorized` on an
internal network could still target internal hosts; this is an explicit,
auditable operator choice.

### DNS rebinding

**Threat:** A target resolves to a public IP on first check, then the DNS
record changes to a private IP before Inspectra connects, bypassing the
initial SSRF check.

**Mitigation:**
- DNS is resolved once per run and the IP is pinned for the connection
  (`src/inspectra/network.py`: `_pinned_get`, IP pinning).
- DNS results are cached per run keyed by hostname
  (`src/inspectra/checks/dns.py`: `_resolve_cached`).
- The connection is not re-resolved inside requests
  (`src/inspectra/network.py`).

**Residual risk:** Multi-homed or load-balanced targets that legitimately
return different IPs per request are pinned to the first-resolved IP.

### Redirect to internal hosts

**Threat:** An HTTP redirect points the scanner at a private/internal
address after the initial target was validated as public.

**Mitigation:**
- Redirects are followed manually (not auto-followed by the HTTP client)
  with per-hop SSRF validation
  (`src/inspectra/network.py`: `_pinned_get`).
- Each redirect hop re-validates the resolved IP against the blocked
  network list (`src/inspectra/safety.py`).
- HTTPS→HTTP downgrade and cross-scheme redirects are rejected
  (`src/inspectra/network.py`).

**Residual risk:** None beyond a blocked redirect being reported as a
check error.

### Slow-loris / resource exhaustion

**Threat:** A slow or unresponsive target holds scanner resources,
reducing throughput or blocking the scan.

**Mitigation:**
- Per-request timeouts on every network operation
  (`src/inspectra/network.py`: `DEFAULT_TIMEOUT`, connect/read timeouts).
- Per-host concurrency capped at 2 in-flight requests
  (`src/inspectra/network.py`: `RateLimitedClient`, `max_per_host=2`).
- Global concurrency capped at `--concurrency` (default 4)
  (`src/inspectra/orchestrator.py`: `ThreadPoolExecutor`).

**Residual risk:** A very large number of distinct targets scanned
concurrently could still consume resources; bounded by `--concurrency`.

### Accidental scanning of third parties

**Threat:** An operator accidentally scans a host they do not own or have
not authorized, causing abuse complaints or legal exposure.

**Mitigation:**
- Explicit `--authorized` consent flag required for scans
  (`src/inspectra/cli.py`).
- Consent banner printed at scan start (`src/inspectra/cli.py`).
- `--allow-private` opt-in required before private-IP targets are scanned
  (`src/inspectra/cli.py`, `src/inspectra/safety.py`).
- Scan header banner states target and that it is a home-lab/authorized
  assessment.

**Residual risk:** `--authorized` is a self-attestation; Inspectra cannot
cryptographically verify operator consent.

### Evidence tampering

**Threat:** An attacker with write access to report files modifies findings
or evidence to hide issues or fabricate results.

**Mitigation:**
- `evidence_hash` (SHA-256 of canonical JSON evidence, truncated to 16
  chars) is computed on every finding
  (`src/inspectra/orchestrator.py`: `_evidence_hash`).
- `evidence_hash` is emitted in JSON reports and SARIF
  `properties.evidenceHash` (`src/inspectra/report/json_report.py`,
  `src/inspectra/report/sarif_report.py`).
- Replay serves fixed fixtures so a replayed report is deterministic and
  comparable (`src/inspectra/replay.py`).

**Residual risk:** An attacker with write access to the report file can
edit both findings and `evidence_hash` together; hash verification
requires an independently stored original.

## 4. Authorization model

Inspectra requires explicit operator consent before scanning:

- `--authorized` flag must be present (`src/inspectra/cli.py`).
- A consent/authorization banner is printed at the start of every scan
  (`src/inspectra/cli.py`).
- `--allow-private` is an additional opt-in required to scan private IP
  ranges; it only takes effect together with `--authorized`
  (`src/inspectra/cli.py`, `src/inspectra/safety.py`).

**What it enforces:** refusal to run without `--authorized`; refusal to
scan private targets without `--allow-private`.

**What it does not enforce:** cryptographic proof of target ownership or
third-party consent; scope limitation to a specific domain list.

## 5. Redaction

Secrets are redacted from finding evidence before any reporter
serializes them, applied as a single choke point in the orchestrator
(`src/inspectra/orchestrator.py`, `src/inspectra/redact.py`).

**Redacted:**
- Header values for `authorization`, `cookie`, `set-cookie`,
  `x-api-key`, `proxy-authorization`
  (`src/inspectra/redact.py`: `SENSITIVE_HEADERS`, `HEADER_LINE_PATTERN`).
- `key=value` / `key: value` secrets matching
  `api_key|secret|token|password`
  (`src/inspectra/redact.py`: `SECRET_PATTERN` =
  `r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*(?!\[REDACTED[:\]])\S+"`).
- JWTs (three base64url segments)
  (`src/inspectra/redact.py`: `JWT_PATTERN` =
  `r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"`).
- URL userinfo credentials (`scheme://user:pass@host`)
  (`src/inspectra/redact.py`: `URL_USERINFO_PATTERN`).
- URL query tokens (`?key=value` / `&key=value` for secret-like keys)
  (`src/inspectra/redact.py`: `URL_QUERY_PATTERN`).

**Not redacted (by design):**
- Public hostnames, paths, status codes, headers that are not secret-like.
- The target URL itself (needed to contextualize findings).

`--no-redact` disables redaction with a stderr warning; intended only for
offline, single-operator debugging.

## 6. Evidence integrity

- `evidence_hash` = SHA-256 of canonical JSON of the finding's evidence
  list, truncated to 16 characters
  (`src/inspectra/orchestrator.py`: `_evidence_hash`).
- Computed after redaction, so redacted evidence is what is hashed
  (`src/inspectra/orchestrator.py`).
- Emitted on every `Finding` and in JSON reports and SARIF
  `properties.evidenceHash`
  (`src/inspectra/report/json_report.py`,
  `src/inspectra/report/sarif_report.py`).

**What it covers:** the evidence text associated with a finding at scan
time.

**What an attacker with write access could do:** edit both the finding
evidence and its `evidence_hash` in a stored report; hash integrity is
only meaningful when the original hash is stored or verified
independently (e.g. against a baseline saved at scan time).

## 7. Supply chain

- Pinned dependencies declared in `pyproject.toml`; no post-install
  scripts.
- CI runs `ruff check`, `ruff format --check`, `mypy --strict`, and
  `pytest --cov=inspectra --cov-fail-under=80` on every push/PR
  (`.github/workflows/ci.yml`).
- Publishing to PyPI uses GitHub Actions OIDC trusted publishing
  (`.github/workflows/release.yml`: `id-token: write`,
  `pypa/gh-action-pypi-publish`, `environment: pypi`); no long-lived
  PyPI password or `.pypirc` is stored in the repository.
