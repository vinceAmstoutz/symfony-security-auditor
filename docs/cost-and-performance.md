# Cost & Performance

Tune the audit for speed, token spend, and provider rate limits. The quickest knob is a [profile](#profiles); the levers below take you further when you need to.

> See also: [Configuration](configuration.md) · [CI Integration](ci.md) · [FAQ](faq.md)

## Profiles

`profile` presets the cost/speed/depth levers in a single line. A profile only fills the keys you leave unset — any explicitly configured key always wins, so you can start from a preset and override just what you need.

| Profile | Iterations | Lean pre-scan | Code slicing | Concurrency (attacker / reviewer) | PoC synthesis | Best for |
| --- | --- | --- | --- | --- | --- | --- |
| `fast` | 1 | ✅ | ✅ | 4× / 4× | — | PR / pre-commit feedback, large repos |
| `balanced` _(default)_ | 3 | — | — | 1× / 1× | — | Nightly CI, most projects |
| `thorough` | 3 | — | — | 1× / 1× | ✅ | Release gates, deep audits |

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    profile: 'fast'
```

Each key a profile sets is documented in [Configuration → `audit.*`](configuration.md#audit--orchestrator-knobs).

## Speed & cost levers

- **Split-model** — pairing a powerful attacker with a cheap reviewer (`attacker_model` + `reviewer_model`) is the single biggest cost lever: the Reviewer phase alone often runs ~20× cheaper than on the attacker's model. See [Split-Model Setup](configuration.md#split-model-setup).
- **Concurrency** — `audit.attacker_max_concurrent` and `audit.reviewer_max_concurrent` resolve several LLM calls at once on platforms with an async transport; `4`–`8` (within your rate limits) cuts each phase's wall-clock roughly proportionally. Cache hits short-circuit, so only the misses are dispatched.
- **Caching** — content-hash caching skips identical attacker chunks and reviewer verdicts across runs, and Anthropic prompt caching (`cache_retention` in `ai.yaml`) gives a ~90% input-token discount on cache hits. Both are on by default; see [Configuration → `cache.*`](configuration.md#cache--caching-layers).
- **Lean pre-scan & code slicing** — `audit.static_prescan.lean_mode` drops marker-free files and `audit.code_slicing.enabled` trims large files to security-relevant lines; both cut tokens and are on under the `fast` profile.
- **Budget guards** — cap a run with `audit.budget.max_tokens` / `audit.budget.max_cost_usd`, and preview spend with `audit:run --dry-run` before committing to a full run. The preview's token counts are a heuristic projection, not the real per-call usage a completed run reports: the file contents plus, for each chunk, the system prompt and the project mapping (routes, firewalls, voters, forms) that every chunk's request carries, so a project with many routes is priced for them. The standalone binary runs it without a provider credential, so you can price a project before signing up for one.

## Coverage critic

`audit.coverage_critic.enabled: true` adds one pass after the attacker/reviewer loop. The attacker model reads a summary of the run — the routes and their guards, the voters, the file groups the attacker analyzed with each file's coverage status, and the confirmed findings, never a file's contents — and names up to `audit.coverage_critic.max_gaps` (default `5`) gaps: files no chunk showed together. Each gap is then analyzed as one targeted attacker chunk on those files, led by the critic's hypothesis, and what it finds goes through the reviewer like any other finding.

- **Extra cost** — one critic call, whose input grows with the number of routes (the same route map every attacker chunk carries) and is otherwise capped (200 file groups, 100 findings), plus at most `max_gaps` chunks of a few files each, plus the review of what they find. Every call is booked on `audit.budget` like the others; `audit:run --dry-run` does not price the critic.
- **When to enable** — when chunking cannot keep related paths together: a feature with a bulk, import or export action beside a guarded single-item one, a handler reached from a route, a console command and a Messenger message alike, or a large project audited with `audit.chunking.strategy: type`. Leave it off for quick PR runs and small projects, where each chunk already holds its feature.
- **Caching** — a gap's chunk is cached under its hypothesis, so a rerun that names the same gap in the same words reads it from the cache; the critic's own call is made on every run.

## Avoiding rate limits (`429`)

Two layers keep you inside provider quotas:

- **Reactive (always on)** — transient `429`/`5xx` responses are retried with jittered exponential backoff (`audit.retry.*`), honoring server `Retry-After` headers and, on a `429`, any longer wait the provider names: the one its message asks for (`Please try again in 8.064s.`) or OpenAI's token-window reset (`x-ratelimit-reset-tokens`).
- **Proactive (opt-in)** — set `audit.rate_limit.requests_per_minute`, `audit.rate_limit.input_tokens_per_minute`, and/or `audit.rate_limit.output_tokens_per_minute` to your provider tier so a token-bucket limiter keeps the steady state inside quota. See [Configuration → `audit.rate_limit.*`](configuration.md#auditrate_limit--proactive-throttling).

Still throttled? Lower `audit.max_iterations`, raise `audit.reviewer_batch_size` (fewer reviewer calls), keep `*_max_concurrent` within your tier, switch the reviewer to a cheaper model with higher limits, and run nightly instead of on every PR.
