# Security Policy

`symfony-security-auditor` is a security tool. Vulnerabilities in the auditor
itself are taken seriously and handled privately.

## Supported Versions

Security fixes are released for the latest stable `1.x` minor. Earlier minors no
longer receive patches once a newer one is published — pin to the latest `1.x`
in production.

| Version | Supported          |
| ------- | ------------------ |
| `1.x`   | :white_check_mark: |
| `< 1.0` | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Public disclosure before a fix is
available puts every host application at risk.

Report privately via
[GitHub Security Advisories](https://github.com/vinceamstoutz/symfony-security-auditor/security/advisories/new).

Include in your report:

- A description of the vulnerability and the threat model it breaks.
- Steps to reproduce — ideally a minimal failing case (target snippet, bundle
  configuration, LLM provider).
- Affected versions (run
  `composer show vinceamstoutz/symfony-security-auditor`).
- Potential impact: information disclosure, prompt injection, false-negative
  amplification, supply-chain risk, etc.
- A suggested fix or mitigation, if you have one.

## Response Timeline

- **72 hours** — initial acknowledgement.
- **7 days** — triage decision (accepted / declined / needs more info), and an
  estimated fix window for accepted reports.
- **30 days** — target for a patched release for accepted high/critical severity
  reports. Lower-severity fixes ship in the next regular release.

You will be credited in the published advisory and `CHANGELOG.md` unless you
prefer to remain anonymous.

## Scope

In scope:

- Code under `src/` and `config/` shipped by this bundle.
- Bundle configuration parsing (`SymfonySecurityAuditorBundle`).
- The `audit:run` console command.
- LLM seam handling (`Audit\Domain\Port\LLMClientInterface` and its default
  `SymfonyAiLLMClient` adapter) — in particular, secret scrubbing, prompt
  injection from scanned files, and budget-bypass paths.

Out of scope (report upstream):

- Vulnerabilities in `symfony/ai`, Symfony framework components, or third-party
  LLM providers.
- Vulnerabilities in `composer audit` or its advisory data source.
- Findings produced by the auditor against an application you own — those are
  findings about your application, not about the auditor.

## Public Disclosure

Once a fix is released, the advisory is published and credited. The CHANGELOG
entry will reference the CVE (if assigned) under `### Security`.
