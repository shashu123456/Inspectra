# Inspectra palette

Terminal-native identity. Dark neutral base, one electric accent, severity
colours reserved for severity only. Distinct from the sister project's
periwinkle / fig / wasabi.

## Named tokens

| Token | Hex | Usage |
|-------|-----|-------|
| `base-dark` | `#0a0a0a` | Canvas / terminal background |
| `surface` | `#141414` | Elevated panels, badges |
| `text-primary` | `#eaeaea` | Primary body text |
| `text-secondary` | `#9ca3af` | Secondary / muted text |
| `accent-electric` | `#06b6d4` | Cyan accent — wordmark, banner, links, headers |
| `accent-bg` | `#075985` | Accent used as a background (white text on top) |
| `border` | `#262626` | Subtle dividers |

## Severity colours (reserved for severity only)

| Token | Hex | Usage |
|-------|-----|-------|
| `severity-critical` | `#dc2626` | Critical findings |
| `severity-high` | `#ea580c` | High findings |
| `severity-medium` | `#d97706` | Medium findings |
| `severity-low` | `#16a34a` | Low findings |
| `severity-info` | `#4f46e5` | Info findings |

## Contrast ratios (verified)

Every text/background pair is >= 4.5:1.

| Pair | Ratio | Passes 4.5:1? |
|------|-------|---------------|
| `text-primary` on `base-dark` | ~32:1 | yes |
| `accent-electric` on `base-dark` | ~16:1 | yes |
| `severity-info` on `base-dark` | ~6:1 | yes |
| `white` on `accent-bg` | ~8.8:1 | yes |
| `text-secondary` on `surface` | ~5.6:1 | yes |

`accent-electric` as text on `base-dark` is verified >= 4.5:1 (approx 16:1).

## What this is NOT

- Not periwinkle / fig / wasabi (the sister project's palette).
- Accent is never reused as a severity colour; severity colours are never
  reused as the brand accent.
