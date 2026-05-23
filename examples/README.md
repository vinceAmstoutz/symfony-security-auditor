# Examples

End-to-end demonstrations and configuration recipes for
`vinceamstoutz/symfony-security-auditor`.

> [!WARNING]
>
> Everything under [`vulnerable-app/`](vulnerable-app/) is **intentionally
> vulnerable** and exists only to show the auditor in action. Do **not** deploy
> any of it.

## Layout

| Path                                                     | What it shows                                                                                                                    |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| [`configs/ci-optimized.yaml`](configs/ci-optimized.yaml) | Split-model (large attacker, fast reviewer) for scheduled CI runs. Cache + prompt caching on. Targets accuracy at moderate cost. |
| [`configs/cost-aware.yaml`](configs/cost-aware.yaml)     | One small model, single iteration, tools disabled. Smallest possible bill. Use when you need rough triage of a large monorepo.   |
| [`configs/dev-fast.yaml`](configs/dev-fast.yaml)         | Local Ollama backend (no API key, no spend). Higher recall via lower `min_confidence` for exploratory development scans.         |
| [`vulnerable-app/`](vulnerable-app/)                     | Tiny Symfony 7 skeleton with deliberate flaws (broken access control, IDOR, SQL injection by concatenation, mass assignment).    |

## Reproducing each example

### Configurations

Drop any file from `configs/` into a real Symfony project as
`config/packages/symfony_security_auditor.yaml` and run:

```bash
bin/console audit:run
```

Expect: a console report whose risk level depends on what your codebase actually
contains. The split-model config is the recommended starting point for CI; the
cost-aware config trades recall for spend; the dev-fast config keeps every call
local.

### Vulnerable demo app

```bash
cd examples/vulnerable-app
composer install
export ANTHROPIC_API_KEY=…           # or set up Ollama and uncomment the
                                     # ollama: block in config/packages/ai.yaml
bin/console audit:run
```

Expect: a non-zero exit code and a report listing roughly four findings — one
broken-access-control on `UserController::deleteAction()`, one IDOR on
`UserController::showAction()`, one SQL-injection on
`SearchController::queryAction()`, and one mass-assignment on the `User` entity.
Exact wording and severity vary by model.

## Files in this directory are not shipped to Packagist

`examples/` is listed in [`.gitattributes`](../.gitattributes) with
`export-ignore`, so it is excluded from `composer require` payloads and from the
Packagist tarball. It exists only in the Git repository as documentation.
