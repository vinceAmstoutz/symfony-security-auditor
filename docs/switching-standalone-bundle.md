# Switching Between the Standalone Binary and the Bundle

The binary and the bundle run the same audit with the same `audit` options and report formats. This page moves an existing setup from one to the other.

> See also: [Configuration](configuration.md) · [Extending](extending.md) · [CI](ci.md)

## Which one to use

| You need | Use |
| --- | --- |
| Nothing added to the audited project, or one install for many projects | Binary |
| `init`, `doctor`, `self-update` or the `auth:*` key store | Binary |
| Custom services or decorated ports ([Extending](extending.md)) | Bundle |
| The auditor pinned in the application's `require-dev` | Bundle |
| The `cache` or `failover` platform, `.env` files or the Symfony secrets vault | Bundle |

## The same setup in both forms

Bundle:

```yaml
# config/packages/ai.yaml
ai:
    platform:
        anthropic:
            api_key: '%env(ANTHROPIC_API_KEY)%'
```

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-5'
    reviewer_model: 'claude-haiku-5-5'
    scan:
        included_paths: ['src', 'config', 'templates']
    audit:
        baseline: '.security-baseline.json'
        budget:
            max_cost_usd: 5
```

Binary:

```yaml
# ~/.config/symfony-security-auditor/config.yaml
platform:
    anthropic:
        api_key: '%env(ANTHROPIC_API_KEY)%'
attacker_model: 'claude-opus-5'
reviewer_model: 'claude-haiku-5-5'
audit:
    budget:
        max_cost_usd: 5
```

```yaml
# .symfony-security-auditor.yaml, committed at the project root
scan:
    included_paths: ['src', 'config', 'templates']
audit:
    baseline: '.security-baseline.json'
```

## From the bundle to the binary

### Configure

1. [Install the binary](../README.md#1-install).
2. Run `init` with the provider and model you use now. It installs the provider bridge and writes `config.yaml` (`%APPDATA%\symfony-security-auditor\config.yaml` on Windows): `symfony-security-auditor init --provider=anthropic --model=claude-opus-5-5`.
3. Copy the keys of `config/packages/symfony_security_auditor.yaml` into `config.yaml` without the `symfony_security_auditor:` root. Replace your application's `%parameters%` with their values. Give `cache.dir` as an absolute path.
4. Copy the `ai.platform` block of `config/packages/ai.yaml` under `platform:`, in the same shape. With several platforms, set `provider:` to the one your `PlatformInterface` alias names and install each extra bridge by hand ([Switching providers](configuration.md#switching-providers)).
5. For a subscription set with `cli_agent.platform`, run `init --provider=claudecode` (or `codex`) instead and drop the `cli_agent` key ([subscription](configuration.md#running-on-a-subscription)).
6. Provide the API key. The binary reads neither `.env` files nor the secrets vault: export the variable `platform:` names or store it once with `auth:set`. In `platform:` it resolves only `%env(VAR)%` and `%env(file:VAR)%` ([Providing the API key](configuration.md#providing-the-api-key)).
7. Move the settings that belong to the repository (paths, baseline, `audit.fail_on`, `audit.report_path_prefix`) to a committed `.symfony-security-auditor.yaml` at the project root. It may not set `platform`, `provider`, `cache`, `privacy`, `audit.custom_skills`, `audit.output`, `audit.tools_scope`, `scan.import_sarif`, `scan.custom_risk_patterns` or `scan.secret_scrubbing`, nor hold a `%env()%` value: keep those in `config.yaml` ([Per-project overrides](configuration.md#per-project-overrides)).
8. Check the setup: `symfony-security-auditor doctor --check-connection`.

### Update commands, CI and MCP

| Bundle | Binary |
| --- | --- |
| `bin/console audit:run` (or `audit`) | `symfony-security-auditor audit` |
| `bin/console audit:diff`, `audit:trend`, `audit:baseline` | `symfony-security-auditor audit:diff`, `audit:trend`, `audit:baseline` |
| `bin/console mcp:serve` | `symfony-security-auditor mcp:serve` |

- **GitHub Action:** set `mode: standalone`. It configures Anthropic with `claude-opus-5-5`; a committed `.symfony-security-auditor.yaml` may pick another `model` ([Reusable GitHub Action](ci.md#reusable-github-action)).
- **Other CI, or another provider:** install the binary, run `symfony-security-auditor init --no-interaction --provider=<provider> --model=<model>`, then `symfony-security-auditor audit`. Drop `composer install` if only the audit needed it. Pass the key as a secret environment variable.
- **CI user config:** a runner's `config.yaml` holds only what `init` wrote. The repository's `.symfony-security-auditor.yaml` still applies. Write any key it may not set into `config.yaml` in a step after `init`.
- **Cache:** it moves from `var/cache/<env>/symfony_security_auditor/` to `~/.cache/symfony-security-auditor` (`%LOCALAPPDATA%\symfony-security-auditor` on Windows). Point CI cache steps at it.
- **MCP:** replace `"command": "php", "args": ["/absolute/path/to/bin/console", "mcp:serve"]` with `"command": "symfony-security-auditor", "args": ["mcp:serve"]`. Start it from the project: it reads the `.symfony-security-auditor.yaml` of the folder it starts in. Store the key with `auth:set`, since a desktop client does not pass your shell's variables ([`mcp:serve`](configuration.md#mcpserve-model-context-protocol-server)).

### What you lose

- Custom services, decorated ports and every other extension point of [Extending](extending.md). Configuration-only rules (`audit.custom_skills`, `scan.custom_risk_patterns`) keep working from `config.yaml`.
- The `cache` and `failover` platforms.
- `.env` files, the secrets vault and, in `platform:`, every env processor but `file:`.

Once the binary audits as before, remove the bundle: `composer remove --dev vinceamstoutz/symfony-security-auditor`. Keep `ai.yaml` and the bridge if your application uses them.

## From the binary to the bundle

### Configure

1. Require the bundle (PHP 8.3+ and Symfony 7.4+): `composer require --dev vinceamstoutz/symfony-security-auditor`. Flex registers it and creates `config/packages/symfony_security_auditor.yaml` ([without Flex](configuration.md#manual-setup-without-flex)).
2. Require your provider's bridge, for example `composer require symfony/ai-anthropic-platform` ([packages](configuration.md#supported-platforms)).
3. Move the `platform:` block, unchanged, under `ai: platform:` in `config/packages/ai.yaml`.
4. Move every other key of `config.yaml` and `.symfony-security-auditor.yaml` under `symfony_security_auditor:` in `config/packages/symfony_security_auditor.yaml`. Where both files set a key, keep the project file's value. The bundle reads neither file.
5. Double each `%` that your risk patterns, scrubbing patterns and skill instructions hold as text (`%s` becomes `%%s`): the bundle reads a `%…%` pair as a parameter.
6. Put the API key in `.env.local`, the secrets vault (`bin/console secrets:set ANTHROPIC_API_KEY`) or the environment: the bundle does not read the `auth:set` store ([In a Symfony application](configuration.md#in-a-symfony-application)). Then run `symfony-security-auditor auth:remove`.

Replace the standalone-only keys:

| Binary | Bundle |
| --- | --- |
| `platform:` | `ai.platform` in `config/packages/ai.yaml` |
| `provider:` | Nothing with one platform. With several, alias `Symfony\AI\Platform\PlatformInterface` to `@ai.platform.<name>` in `config/services.yaml` ([details](configuration.md#several-platforms-in-a-symfony-application)) |
| `provider: claudecode` or `codex` | `cli_agent.platform: claudecode` or `codex`, with `symfony/ai-claude-code-platform` or `symfony/ai-codex-platform` required; a `cli_binary:` setting becomes `cli_agent.cli_binary` and an `effort:` setting `cli_agent.effort` |
| `http_timeout:` | `framework.http_client.default_options.timeout` |

### Update commands, CI and MCP

- Run `bin/console audit:run` in place of `symfony-security-auditor audit`. The report commands and `mcp:serve` follow the table above. `init`, `doctor`, `self-update` and `auth:*` have no bundle equivalent: update with `composer update`.
- **GitHub Action:** remove `mode: standalone` (`bundle` is the default). Elsewhere, run `composer install`, then `php bin/console audit:run`.
- **Cache:** remove an absolute `cache.dir` to use the default under `var/cache/<env>/symfony_security_auditor/`.
- **MCP:** use `"command": "php"` and `"args": ["/absolute/path/to/bin/console", "mcp:serve"]`.
