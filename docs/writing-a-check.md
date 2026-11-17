# Writing a Custom Check for Inspectra

Custom checks let you extend Inspectra with your own assessment logic without
modifying the core codebase.

## Check module template

Create a Python file that exposes three attributes:

```python
RULE_ID = "CUST-001"
TITLE = "Human-readable one-sentence title"


def check(target, context):
    # Perform your assessment using context.client (an HTTP client)
    # Return a list of Finding objects
    return []
```

### Required attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `RULE_ID` | `str` | Unique rule identifier (e.g. `CUST-001`) |
| `TITLE` | `str` | One-sentence human-readable title |
| `check` | `callable` | `check(target, context) -> list[Finding]` |

The `check` function receives:
- `target`: a `Target` with `hostname`, `base_url`, `scheme`, `port`
- `context`: a `ScanContext` with `context.client` (an HTTP client with `get(url)`)

### Example: security.txt

See `examples/custom_checks/security_txt.py` for a complete worked example that
checks `/.well-known/security.txt`.

## Loading custom checks

```bash
inspectra scan https://example.com --yes --rules-dir examples/custom_checks
```

Multiple `--rules-dir` flags are allowed. Custom findings appear in the
terminal table and in JSON/SARIF output with their own rule IDs.

## Validation

Inspectra validates each custom check module before running:

- Missing `RULE_ID`, `TITLE`, or `check` → error naming the file and attribute
- Duplicate `RULE_ID` against another custom check or built-in → error
- Import failure → error with the underlying cause
- `check` not callable → error

All validation errors exit with code 2.

## Listing checks

```bash
inspectra scan https://example.com --yes --list-checks
```

Lists every built-in and loaded custom check with ID, title, and source.
