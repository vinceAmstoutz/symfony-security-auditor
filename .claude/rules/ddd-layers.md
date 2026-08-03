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

## The framework-specific boundary

`Infrastructure` is split again in `deptrac.yaml`: a **`SymfonyProfile`** layer
holds the parts that only make sense for a Symfony application —
`Infrastructure/Prompt/**`, the Symfony source parsers in
`Infrastructure/Scan/`, and the container-building classes in
`Infrastructure/Config/`. Everything else under `Infrastructure/` may **not**
depend on it, so the audit engine stays reusable for a non-Symfony target.

When you add a class that reads Symfony attributes, Symfony configuration files
or the Symfony container, or that writes Symfony vocabulary into a prompt, put
it where `SymfonyProfile` already collects it. Wire it from `Command`, the
bundle class or `Standalone` — never from a portable `Infrastructure` class. See
[`docs/architecture.md`](../../docs/architecture.md#the-framework-specific-boundary).
