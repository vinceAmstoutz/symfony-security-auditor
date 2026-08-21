# Upgrading to 2.0

Every change below is breaking. None of them requires a code change unless you
implement one of this bundle's PHP interfaces or gate CI on an exit code — most
projects only need to re-read the two default flips.

Full detail for each item, including root cause and exact file paths, is in
[`CHANGELOG.md`](CHANGELOG.md). The policy these changes follow is in
[`docs/versioning.md`](docs/versioning.md).

## At a glance

| What changed                               | Do you need to act?                            |
| ------------------------------------------ | ---------------------------------------------- |
| `audit.fail_on` defaults to `high`         | Only if a HIGH-risk audit must keep passing CI |
| `model` defaults to `claude-opus-5`        | Only if you relied on the unconfigured default |
| `max_output_tokens` defaults to `8192`     | No                                             |
| `cache.prompt_caching` removed             | Yes, if the key is still in your configuration |
| Exit code `3` for a failed audit           | Only if CI branches on `1`                     |
| `*::create()` factories removed            | Only if you call them                          |
| `PricingProviderInterface` widened         | Only if you implement it                       |
| Eight Domain ports now `@internal`         | Only if you implement one                      |
| Batch client signatures take value objects | Only if you implement a batch-capable client   |

## Configuration

### `audit.fail_on` now defaults to `high`

A report whose aggregate risk level is HIGH now exits `1` and fails CI. Through
1.x only `CRITICAL` did.

```yaml
symfony_security_auditor:
    audit:
        fail_on: 'critical' # restores the 1.x gate
```

`--fail-on=critical` does the same for a single run. This flip was announced in
`docs/versioning.md` throughout 1.x.

### `model` now defaults to `claude-opus-5`, `max_output_tokens` to `8192`

Only the _unconfigured_ experience changes. `claude-opus-4-8` remains a valid,
priced, explicitly-settable model:

```yaml
symfony_security_auditor:
    model: 'claude-opus-4-8'
    max_output_tokens: 4096
```

The cap moved because on a current Claude model `max_tokens` bounds thinking and
response text together, so `4096` left less room for a full finding than the
number suggests. `init --no-interaction` (and therefore the `SSA_INIT` installer
flag and the GitHub Action's standalone mode) writes the new default too.

### `cache.prompt_caching` is removed

The key had no effect since 1.7. It is now rejected rather than ignored, so
**leave it in place and your configuration fails to validate**:

```text
Unrecognized option "prompt_caching" under "symfony_security_auditor.cache"
```

Delete it. For a longer Anthropic cache window, set `cache_retention: long` on
the `anthropic` platform in `config/packages/ai.yaml`; OpenAI and Gemini cache
automatically.

### `max_output_tokens` now reports when it cannot be applied

Only the Anthropic-dialect bridges accept the `max_tokens` option. Setting a
non-default cap against any other model now prints a pre-flight notice naming
the model and the value, instead of silently doing nothing. The dialect is
decided by anchored model-id prefix (`claude-`, `claude.`, `anthropic.`,
`us./eu./apac.anthropic.`) rather than a `claude` substring, so a Bedrock id
keeps its cap and an unrelated model that merely contains "claude" no longer
receives an option its bridge rejects.

## CLI

### Exit code `3` — the audit did not complete

| Code | Meaning                                  |
| ---- | ---------------------------------------- |
| `0`  | Completed, below the `fail_on` threshold |
| `1`  | Completed, and the gate tripped          |
| `2`  | Budget aborted                           |
| `3`  | **New** — no verdict was produced        |

An abort that happens after findings were already validated still writes the
partial report, so treat a `3` as "output incomplete", not "output absent".

`3` covers an invalid `project-path`, an option value the console rejects,
conflicting options, an LLM provider abort, and any unhandled exception — all of
which returned `1` through 1.x, making a crashed auditor indistinguishable from
a working one reporting real vulnerabilities.

A job that gates on findings still checks `1` and needs no change. A job that
wants to alert on tool health should check `3`. The GitHub Action's `exit-code`
output surfaces it unchanged.

## PHP API

### Removed: the wide `create()` factories

Deprecated since 1.13. Pass the value objects to `of()` instead:

| Removed                    | Replacement                                                                                     |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| `Vulnerability::create()`  | `Vulnerability::of()` — `VulnerabilityClassification`, `CodeLocation`, `VulnerabilityNarrative` |
| `SymfonyMapping::create()` | `SymfonyMapping::of()` — `ProjectFileInventory`, `AccessControlMap`                             |
| `LLMResponse::create()`    | `LLMResponse::of()` — `TokenUsageSnapshot`                                                      |

### Removed: `CacheAwarePricingProviderInterface`

Its two methods moved onto `PricingProviderInterface`, which every
implementation must now satisfy:

```php
public function cacheReadPricePerMillionTokens(string $model): float;
public function cacheCreationPricePerMillionTokens(string $model): float;
```

If your pricing source has no cache rates, return
`$this->pricePerMillionInputTokens($model)` from both — that reproduces the old
non-cache-aware behaviour exactly. `CostCalculator` no longer carries the
Anthropic `0.1x`/`1.25x` heuristic, so a provider that returns the base input
rate for Claude models will price cache traffic higher than 1.x did; return the
real rates (the bundled `ModelsDevPricingProvider` does) to keep the discount.

### Narrowed: which Domain ports the BC promise covers

`docs/versioning.md` now
[enumerates the covered ports](docs/versioning.md#domain-ports-extension-points)
instead of covering the whole `src/Audit/Domain/Port/` directory. These eight
are now `@internal` and may change in a `MINOR`:

- `AttackerPromptBuilderInterface`, `ReviewerPromptBuilderInterface`
- `AttackerCacheInterface`, `ContextAwareAttackerCacheInterface`,
  `ReviewerCacheInterface`
- `ReviewerFeedbackSnapshotInterface`
- `BatchCapableLLMClientInterface`, `ToolBatchCapableLLMClientInterface`

Nothing about them stopped working — implement them if they are useful to you,
but pin the bundle's minor version if you do.

### Changed: batch client signatures take value objects

Following from the demotion above:

```php
// 1.x
public function completeBatch(array $requests, int $maxConcurrent): array;
// $requests: list<array{system: string, user: string}>

// 2.0
public function completeBatch(array $requests, int $maxConcurrent): array;
// $requests: list<LLMRequest>
```

`completeBatchWithTools()` likewise takes `list<ToolLLMRequest>` — the same
three fields (`system`, `user`, `tools`) as constructor arguments. The
`LLMRequest::listFromArrays()` / `ToolLLMRequest::listFromArrays()` adapters are
gone.
