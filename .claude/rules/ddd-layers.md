# DDD Layer Rules

Dependency direction: `Command → Application → Domain ← Infrastructure`.

- **Domain** (`src/Audit/Domain/`): pure PHP only. No Symfony, no `symfony/ai`,
  no I/O. Value objects are immutable.
- **Application** (`src/Audit/Application/`): orchestration only. Depends on
  Domain interfaces (ports). Never imports Infrastructure classes directly —
  only through injected interfaces.
- **Infrastructure** (`src/Audit/Infrastructure/`): implements Domain ports. May
  import `symfony/ai`, filesystem, etc.
- **Command** (`src/Command/`): thin console adapter. Delegates to
  `RunAuditUseCase`, delegates rendering to `ReportRenderer`.

**Never** import an Infrastructure class into Domain or Application. If
Application needs I/O, define an interface in Domain and implement it in
Infrastructure.

## A new port is `@internal` by default

`Port/` is where the DDD layout puts any interface the Application layer depends
on — not a list of things users are invited to implement. So **every new
interface added under `src/Audit/Domain/Port/` carries the `@internal` tag**.

Joining the backward-compatibility promise is a separate, deliberate step: add
the port to the enumerated list in
[`docs/versioning.md`](../../docs/versioning.md#domain-ports-extension-points),
explain in [`docs/extending.md`](../../docs/extending.md) what implementing it
achieves, and drop the tag in the same commit. Before 2.0 the promise was a
directory glob, so ~30 internal collaboration seams became frozen public API by
accident; the tag-first default is what stops that from happening again.

## The framework-specific boundary

`Infrastructure` is split again in `deptrac.yaml`: a **`SymfonyProfile`** layer
holds the parts that only make sense for a Symfony application —
`Infrastructure/Prompt/**`, the Symfony source parsers in
`Infrastructure/Scan/`, and `Infrastructure/Config/Registrar/Symfony/**` with
the `SymfonyProfile` that lists them. Everything else under `Infrastructure/`
may **not** depend on it, so the audit engine stays reusable for a non-Symfony
target.

The test is knowledge of the **audited** framework, not use of Symfony
components by the auditor itself: the composition roots and the core registrars
build a Symfony container and are still portable. So a class that reads Symfony
attributes or configuration files, or writes Symfony vocabulary into a prompt,
goes where `SymfonyProfile` already collects it — while a collaborator a Laravel
profile would reuse verbatim (the skill registry, the reviewer-feedback
plumbing) stays on the portable side, however close to the prompts it sits. Wire
the profile from `Command`, the bundle class or `Standalone` — never from a
portable `Infrastructure` class. See
[`docs/architecture.md`](../../docs/architecture.md#the-framework-specific-boundary).
