# Inspectra — Safety, Ethics & Legal Guidance

## The Philosophy

> Inspect. Observe. Assess. Explain. Report. **Never exploit.**

Inspectra is a *passive* assessment framework. It observes what a system
willingly reveals to any normal visitor and explains what that means. It
contains no exploitation code, no brute-forcing, no payload delivery, no
denial-of-service logic — and none will be accepted.

## What Inspectra Does

* Sends the same requests a browser or crawler would send (GET).
* Reads responses: headers, certificates, DNS records, robots.txt.
* Probes a small curated path list — only when explicitly enabled.
* Explains and reports what it observed.

## What Inspectra Never Does

* Never exploits a vulnerability or attempts intrusion.
* Never brute-forces credentials or paths.
* Never sends attack payloads, fuzzing input or oversized requests.
* Never performs denial-of-service or resource-exhaustion testing.
* Never bypasses authentication or authorization controls.
* Never stores or exfiltrates discovered data beyond the local report.

## Authorized Use Only

Scanning systems you do not own or do not have **explicit written
permission** to test may be illegal in your jurisdiction — including under
laws such as the US Computer Fraud and Abuse Act, the UK Computer Misuse
Act, and equivalents worldwide.

Inspectra enforces this at three levels:

1. **Authorization gate** — the first run requires agreeing to scan only
   authorized targets (persisted; `--yes` skips the prompt but does not
   remove your responsibility).
2. **Safe defaults** — rate-limited, GET-only, conservative wordlists,
   timeouts everywhere.
3. **No offensive features** — the roadmap deliberately excludes
   exploitation, brute force and attack tooling. See
   [roadmap/architecture-notes.md](roadmap/architecture-notes.md).

## Good-Faith Testing Checklist

Before scanning a target, confirm:

- [ ] You own the system, **or** you hold written authorization (scope
      document, rules of engagement, or explicit permission from the owner).
- [ ] The target is not a production system you are not authorized to touch.
- [ ] Your organization's policies allow the assessment.
- [ ] You understand what the tool sends (plain GET requests, nothing more).

## Reporting a Security Concern

Found an issue in Inspectra itself? See
[SECURITY.md](../SECURITY.md) for responsible disclosure.

## Disclaimer

Inspectra is provided under the MIT License, without warranty of any kind.
The authors and contributors are not liable for misuse. You are solely
responsible for ensuring your use is legal and authorized.
