# DDD Layer Rules

The repository is a monorepo. `packages/core` (namespace
`VinceAmstoutz\SecurityAuditor\`) is framework-agnostic; the root package
(namespace `VinceAmstoutz\SymfonySecurityAuditor\`) is the Symfony bundle.
**Nothing in `packages/core` may depend on anything in `src/`** — deptrac
enforces it.

Inside the core, dependency direction is
`Command → Application → Domain ← Infrastructure`.

- **Domain** (`packages/core/src/Audit/Domain/`): pure PHP only. No Symfony, no
  `symfony/ai`, no I/O. Value objects are immutable.
- **Application** (`packages/core/src/Audit/Application/`): orchestration only.
  Depends on Domain interfaces (ports). Never imports Infrastructure classes
  directly — only through injected interfaces.
- **Infrastructure** (`packages/core/src/Audit/Infrastructure/`): implements
  Domain ports. May import `symfony/ai`, filesystem, etc.
- **Command** (`packages/core/src/Command/`): thin console adapter. Delegates to
  `RunAuditUseCase`, delegates rendering to `ReportRenderer`. It may **not**
  reach the Symfony profile — that is on the far side of the package line.

**Never** import an Infrastructure class into Domain or Application. If
Application needs I/O, define an interface in Domain and implement it in
Infrastructure.

## A new port is `@internal` by default

`Port/` is where the DDD layout puts any interface the Application layer depends
on — not a list of things users are invited to implement. So **every new
interface added under `packages/core/src/Audit/Domain/Port/` carries the
`@internal` tag**.

Joining the backward-compatibility promise is a separate, deliberate step: add
the port to the enumerated list in
[`docs/versioning.md`](../../docs/versioning.md#domain-ports-extension-points),
explain in [`docs/extending.md`](../../docs/extending.md) what implementing it
achieves, and drop the tag in the same commit. Before 2.0 the promise was a
directory glob, so ~30 internal collaboration seams became frozen public API by
accident; the tag-first default is what stops that from happening again.

## The framework-specific boundary

The boundary is the **package** line. `src/` holds only knowledge of the
_audited_ framework: `Infrastructure/Prompt/**` (prompt content and attacker
skills), the Symfony parsers and classifier in `Infrastructure/Scan/`,
`Infrastructure/Config/**` (the Symfony DI wiring and the `SymfonyProfile`),
`Standalone/**` and the bundle class. Everything else lives in `packages/core/`.

The test is knowledge of the **audited** framework, not use of Symfony
components by the auditor itself: `Command/` uses `symfony/console`,
`Infrastructure/Settings/` uses `symfony/yaml`, and both are core. So a class
that reads Symfony attributes or configuration files, or writes Symfony
vocabulary into a prompt, goes in `src/` — while a collaborator a Laravel
package would reuse verbatim (the skill registry, the reviewer-feedback
plumbing, the regex pre-scanner and code slicer) goes in `packages/core/`,
however close to the prompts it sits. Wire the profile from the bundle class or
`Standalone` — never from the core. See
[`docs/architecture.md`](../../docs/architecture.md#the-framework-specific-boundary).
