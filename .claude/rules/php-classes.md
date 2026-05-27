---
paths:
  - "src/**"
---

# PHP Class Rules

## Class Declaration

Every class **must** be declared `final readonly`. The only permitted opt-outs
are documented **context carriers**:

- `Audit\Domain\Model\AuditContext` — pipeline state accumulated across stages.
- `Command\AuditCommandInput` — Symfony Console MapInput requires public mutable
  properties with property-level defaults; promoted readonly constructor params
  are invisible to its reflection.

Each opt-out site declares the reason in a leading code comment and cites this
rule. Anything outside that list must be `final readonly`. If inheritance feels
needed, introduce an interface instead.

## Interfaces & SOLID

Every collaborator that crosses a layer or could plausibly have an alternative
implementation **must** be typed against an interface, not a concrete class.
Follow SOLID strictly:

- **S**RP — see "Single Responsibility" below.
- **O**CP — extend behavior via new implementations of an interface, not by
  modifying existing classes.
- **L**SP — implementations must be substitutable without breaking callers.
- **I**SP — split fat interfaces; consumers depend only on methods they use.
- **D**IP — Application/Domain depend on interfaces; Infrastructure provides the
  implementations (wired in `config/services.php`).

See also: [[ddd-layers]], [[llm-seam]].

## Single Responsibility — One File, One Thing

Each file does exactly one thing. **No exceptions.**

The canonical split lives under `src/Command/`: `AuditCommand` delegates only —
input mapping/validation goes to `AuditCommandInput`, user-facing messaging to
`AuditPresenter`, report persistence to `ReportWriter`, exit-code mapping to
`AuditExitCodeResolver`. Replicate this pattern: thin orchestrator + dedicated
collaborators, each behind an interface.

When you touch a file that bundles responsibilities, extract them into new
classes rather than adding more.

## Custom Exceptions

Never throw raw `\RuntimeException`, `\InvalidArgumentException`,
`\LogicException`, or plain `\Exception` from production code. Every thrown
exception is a domain-meaningful failure and **must** be a project-defined
class.

- Define one custom exception per failure mode, named after the failure (e.g.
  `MalformedLLMResponseException`, `AuditConfigurationException`,
  `ToolNotRegisteredException`).
- Group them under a per-layer namespace: `Audit\Domain\Exception\…`,
  `Audit\Application\Exception\…`, `Audit\Infrastructure\<Adapter>\Exception\…`,
  `Command\Exception\…`.
- Each custom exception extends the closest matching SPL exception
  (`\RuntimeException`, `\InvalidArgumentException`, …) so callers can still
  rely on standard catch hierarchies if they prefer.
- Provide named factory constructors
  (`MalformedLLMResponseException::forNonJsonContent($preview)`) that build a
  precise message at the call site — callers should not assemble error strings.
- `catch` clauses target the **custom** type when possible, never the SPL type,
  so failure semantics remain visible at the catch site.
- Re-throwing third-party exceptions is allowed only when wrapping them into a
  custom exception via `previous`:
  `throw MalformedLLMResponseException::fromJsonException($e);`.

Built-in throwables that are **not** authored by us (`\JsonException`,
`\ValueError`, `\TypeError`, `\Throwable` in broad catches) are fine to consume
— the rule applies to what we _throw_, not what we _catch_.

## Symfony Components First

Prefer Symfony components over hand-rolled or raw PHP equivalents:

- `symfony/string` — string manipulation (no `str_*` chains, no manual slug/case
  logic)
- `symfony/finder` — filesystem traversal (no `scandir`, `glob`, raw
  `RecursiveDirectoryIterator`)
- `symfony/serializer` — (de)serialization (no manual `json_decode` → array
  shuffling for structured payloads)
- `symfony/filesystem`, `symfony/process`, `symfony/console`,
  `symfony/validator`, `symfony/uid`, etc. — use when applicable.

Reach for plain PHP only when no Symfony component fits or when the component
would add a dependency disproportionate to the need — and justify it in the PR
description.

### Domain-layer exception

This rule applies to the **Application, Infrastructure, and Command** layers
only. The **Domain layer** (`src/Audit/Domain/`) is pure PHP by mandate (see
[[ddd-layers]]: _"No Symfony, no `symfony/ai`, no I/O"_) and therefore keeps
native functions — `str_ends_with`, `str_contains`, `trim`, `is_dir`, … — even
where a Symfony component would otherwise be preferred. Do **not** import
`symfony/string`, `symfony/filesystem`, or any other Symfony component into a
Domain class; the layer boundary wins over the components-first preference.

Concretely:

- `symfony/string` (`u()` / `b()`) is used freely in Application /
  Infrastructure / Command, but never in `src/Audit/Domain/`.
- A directory-vs-file predicate (`is_dir` / `is_file`) has no
  `symfony/filesystem` equivalent (`Filesystem::exists()` cannot distinguish the
  two), so those calls stay native at the scanning boundary; use
  `Filesystem::exists()` only where mere existence — not the file type — is the
  actual question.
