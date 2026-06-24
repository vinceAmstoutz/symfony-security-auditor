# Cost & Performance

Tune the audit for speed, token spend, and provider rate limits. The quickest
knob is a [profile](#profiles); the levers below take you further when you need
to.

> See also: [Configuration](configuration.md) · [CI Integration](ci.md) ·
> [FAQ](faq.md)

## Profiles

`profile` presets the cost/speed/depth levers in a single line. A profile only
fills the keys you leave unset — any explicitly configured key always wins, so
you can start from a preset and override just what you need.

| Profile                | Iterations | Lean pre-scan | Code slicing | Concurrency (attacker / reviewer) | PoC synthesis | Best for                              |
| ---------------------- | ---------- | ------------- | ------------ | --------------------------------- | ------------- | ------------------------------------- |
| `fast`                 | 1          | ✅            | ✅           | 4× / 4×                           | —             | PR / pre-commit feedback, large repos |
| `balanced` _(default)_ | 3          | —             | —            | 1× / 1×                           | —             | Nightly CI, most projects             |
| `thorough`             | 3          | —             | —            | 1× / 1×                           | ✅            | Release gates, deep audits            |

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    profile: 'fast'
```

Each key a profile sets is documented in
[Configuration → `audit.*`](configuration.md#audit--orchestrator-knobs).

## Speed & cost levers

- **Split-model** — pairing a powerful attacker with a cheap reviewer
  (`attacker_model` + `reviewer_model`) is the single biggest cost lever, often
  ~20× cheaper than one large model for both roles. See
  [Split-Model Setup](configuration.md#split-model-setup).
- **Concurrency** — `audit.attacker_max_concurrent` and
  `audit.reviewer_max_concurrent` resolve several LLM calls at once on platforms
  with an async transport; `4`–`8` (within your rate limits) cuts each phase's
  wall-clock roughly proportionally. Cache hits short-circuit, so only the
  misses are dispatched.
- **Caching** — content-hash caching skips identical chunks across runs, and
  Anthropic prompt caching (`cache_retention` in `ai.yaml`) gives a ~90%
  input-token discount on cache hits. Both are on by default; see
  [Configuration → `cache.*`](configuration.md#cache--caching-layers).
- **Lean pre-scan & code slicing** — `audit.static_prescan.lean_mode` drops
  marker-free files and `audit.code_slicing.enabled` trims large files to
  security-relevant lines; both cut tokens and are on under the `fast` profile.
- **Budget guards** — cap a run with `audit.budget.max_tokens` /
  `audit.budget.max_cost_usd`, and preview spend with `audit:run --dry-run`
  before committing to a full run.

## Avoiding rate limits (`429`)

Two layers keep you inside provider quotas:

- **Reactive (always on)** — transient `429`/`5xx` responses are retried with
  jittered exponential backoff (`audit.retry.*`), honoring server `Retry-After`
  headers.
- **Proactive (opt-in)** — set `audit.rate_limit.requests_per_minute`,
  `audit.rate_limit.input_tokens_per_minute`, and/or
  `audit.rate_limit.output_tokens_per_minute` to your provider tier so a
  token-bucket limiter keeps the steady state inside quota. See
  [Configuration → `audit.rate_limit.*`](configuration.md#auditrate_limit--proactive-throttling).

Still throttled? Lower `audit.max_iterations`, raise `audit.reviewer_batch_size`
(fewer reviewer calls), keep `*_max_concurrent` within your tier, switch the
reviewer to a cheaper model with higher limits, and run nightly instead of on
every PR.
