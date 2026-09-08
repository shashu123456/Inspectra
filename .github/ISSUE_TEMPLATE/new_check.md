---
name: New check proposal
about: Propose a new assessment check for Inspectra
labels: enhancement, check
---

**Check name**
e.g. `cookie-attributes`

**What it observes**
What does the check look at? (headers, responses, DNS records, …)

**Evidence source**
Which request(s) or cached data does it use? Inspectra prefers reusing the
cached HTTP response over new requests.

**Possible findings and severities**
Sketch the rules: observation → severity → confidence.

**Sample evidence**
Example header/response/DNS data the check would capture.

**References**
Standards, documentation or prior art that support the check.
