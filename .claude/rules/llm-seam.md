---
paths:
  - "src/Audit/Application/Agent/**"
  - "src/Audit/Domain/Port/**"
  - "src/Audit/Infrastructure/LLM/**"
---

# LLM Seam Rules

`LLMClientInterface` (in `Audit\Domain\Port\`) is the **sole seam** between
Application and LLM I/O.

- `AttackerAgent` and `ReviewerAgent` must **never** import any `symfony/ai`
  type. Only `LLMClientInterface` and `LLMResponse` (both in
  `Audit\Domain\Port\`).
- `Audit\Infrastructure\LLM` is the only namespace that may import `symfony/ai`:
  `SymfonyAiLLMClient` implements the Domain ports and builds the
  platform-facing collaborators (`RetryingPlatformInvoker`,
  `SequentialToolLoop`, `BatchWindowResolver`, `ToolConversationWavefront`,
  `InFlightRequestCanceller`, `DegradedAnswerBooker`, `DispatchedRequest`,
  `PlatformResultExtractor`, `PlatformOptionsFactory`, `PlatformToolsMapper`)
  that share the imports. Nothing outside that namespace touches `symfony/ai`.
- Swapping providers (Anthropic → OpenAI → Ollama) must require **zero code
  changes** — only `config/packages/ai.yaml`.
- `LLMResponse::parseJson()` strips markdown fences before decoding — always use
  it; never call `json_decode` directly on LLM output.
- **Transient/parsing errors** (JSON decode failure, generic `Throwable`) in
  agents must be caught and logged; return empty array /
  `reviewerValidated = false` rather than propagating — a single bad chunk must
  not abort the audit.
- **Non-transient provider failures** (`LLMProviderException` from
  `Audit\Domain\Exception\`) must be **rethrown** by agents. These represent
  misconfigured platforms, auth errors, or retired model names that will repeat
  on every call — swallowing them produces a false-negative SAFE result.
  `NonTransientLLMFailureException` (Infrastructure) extends
  `LLMProviderException` (Domain) so agents can catch the Domain type without
  importing Infrastructure.
- **A prompt the model cannot fit** — `LLMRequestTooLargeException` (Domain,
  extends `LLMProviderException`, raised by `RetryingPlatformInvoker` from
  `TransientFailureClassifier::isRequestTooLarge()` and never retried) — is the
  one provider failure an agent recovers from per chunk: it does not repeat on
  every call, so the chunk analyzers hand the chunk to `OversizedChunkRecovery`,
  which splits it in two, instead of rethrowing. Only a single file the model
  cannot fit is recorded as errored — and when that file is under a tenth of the
  refused prompt, the fixed part of the prompt is what leaves no room, so
  `LLMFixedPromptTooLargeException` stops the run. The batch port cannot throw
  for one request, so `ToolConversationWavefront` and `BatchWindowResolver`
  answer a refused request with a `request_too_large` response
  (`LLMResponse::isRequestTooLarge()`, degraded) instead of retrying or
  restarting it, and the concurrent analyzer splits on that answer. The reviewer
  recovers too: a single review records the finding as errored and moves on, and
  `BatchReviewAnalyzer` hands a refused batch to `OversizedReviewBatchRecovery`,
  which splits it.
- **An answer with nothing usable in it is a degraded response, never a
  failure.** A provider that reports the output-limit cut-off or the content
  filter as an exception (`symfony/ai`'s `MaxOutputTokensException`,
  `ContentFilterException`) gets the same `length` / `content-filter` response
  as one that reports it as a finish reason —
  `TransientFailureClassifier::degradedStopReason()` names it, on every call
  path, without a retry. A `MalformedToolCallException` is transient.
- `VulnerabilityFactory::fromArray()` returns `null` on invalid data —
  `fromList()` silently drops nulls. Do not throw from the factory.
- **Structured collection seam.** When `audit.structured_collection: true`
  (default), findings flow through `RecordVulnerabilityTool` (Infrastructure,
  Domain `ToolInterface`) into `VulnerabilityCollector` (Application). The
  tool's JSON-Schema input is the contract — the provider validates each call
  before invocation, so the agent never sees malformed payloads. To extend the
  contract (extra fields, tighter enums), swap
  `RecordVulnerabilityToolFactoryInterface` (Application) at the composition
  root; do **not** introduce post-hoc validation in the agent.
