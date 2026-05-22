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
