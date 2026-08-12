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
  `VULN-{sha1(sha1(type)+sha1(filePath)+sha1(lineStart))[0..7]}` (no microtime,
  no title). Each field is hashed individually before joining — mirroring
  `ChunkContextKeyDeriver::derive()` — so a digit shifting across the
  `filePath`/`lineStart` boundary (e.g. `src/Foo1`+`23` vs `src/Foo`+`123`)
  can't collide. Do not change this scheme without preserving that
  per-field-hash-then-join property.
- Vulnerability `fingerprint`/`attackerFingerprint` (baseline/diff/trend
  identity) is `SSA-{sha1(sha1(type).sha1(filePath).sha1(title))[0..11]}` — each
  field is hashed individually before joining so a delimiter shift across a
  field boundary (e.g. `title` starting with the same bytes that end `filePath`)
  cannot collide two different findings onto the same fingerprint. Do not revert
  to hashing a delimiter-joined string of the raw fields.
- Adding a `ProjectFileType` case requires mapping it in
  `ProjectFileType::archetype()` — the `match` is exhaustive, so an unmapped
  case throws at runtime, and `SurfaceArchetypeTest` fails first.
  `SurfaceArchetype` is the framework-neutral shape core logic switches on; keep
  `HTTP_ENTRYPOINT` meaning a _route-guarded_ surface, since
  `isControllerLike()` delegates to it and it decides which files reach the
  access-control and form-binding maps.
- Adding a `VulnerabilityType` case requires updating `category()`,
  `owaspReference()`, `owaspReferenceUrl()`, and `cwe()` — nothing else changes.
- Adding a `VulnerabilitySeverity` case requires updating `score()`, `label()`,
  `isExploitable()`, and the `riskLevelEnum()` thresholds in `AuditReport`
  (`riskLevel()` derives its string from that enum).
- `RiskLevel` is the ordered aggregate-risk scale (`safe` … `critical`) used by
  the `audit.fail_on` CI gate; `RiskLevel::isAtLeast()` is the comparison.
