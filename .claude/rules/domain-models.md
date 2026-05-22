---
paths:
  - "src/Audit/Domain/**"
---

# Domain Model Rules

- All Domain models are **immutable** (`readonly` properties).
- State changes return new instances (copy-on-write): follow
  `withReviewerValidation()` / `withElevatedSeverity()` pattern on
  `Vulnerability`.
- `AuditContext` is the **only** intentionally mutable object — it is the
  pipeline accumulator. All other Domain models are immutable.
- `AuditReport` is created exactly once via `AuditReport::fromContext()` after
  the pipeline finishes. It captures only `validatedVulnerabilities()`.
- Vulnerability `id` is deterministic:
  `VULN-{sha1(type+filePath+lineStart+microtime)[0..7]}` — do not change this
  scheme.
- Adding a `VulnerabilityType` case requires updating `category()` and
  `owaspReference()` — nothing else changes.
- Adding a `VulnerabilitySeverity` case requires updating `score()`, `label()`,
  `isExploitable()`, and the `riskLevel()` thresholds in `AuditReport`.
