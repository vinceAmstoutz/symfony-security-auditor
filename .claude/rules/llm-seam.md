---
paths:
  - "src/Audit/Application/Agent/**"
  - "src/Audit/Domain/Port/**"
  - "src/Audit/Infrastructure/LLM/**"
---

# LLM Seam Rules

`LLMClientInterface` (in `Audit\Domain\Port\`) is the **sole seam** between Application and LLM I/O.

- `AttackerAgent` and `ReviewerAgent` must **never** import any `symfony/ai` type. Only `LLMClientInterface` and `LLMResponse` (both in `Audit\Domain\Port\`).
- `Audit\Infrastructure\LLM` is the only namespace that may import `symfony/ai`: `SymfonyAiLLMClient` implements the Domain ports and builds the platform-facing collaborators that share the imports (listed in [`docs/architecture.md`](../../docs/architecture.md#symfonyaillmclient)). Nothing outside that namespace touches `symfony/ai`.
- Swapping providers (Anthropic → OpenAI → Ollama) must require **zero code changes**: only `config/packages/ai.yaml`.
- `LLMResponse::parseJson()` strips markdown fences before decoding. Always use it; never call `json_decode` directly on LLM output.
- **Transient/parsing errors** (JSON decode failure, generic `Throwable`) in agents must be caught and logged; return empty array / `reviewerValidated = false` rather than propagating: a single bad chunk must not abort the audit.
- **Non-transient provider failures** (`LLMProviderException` from `Audit\Domain\Exception\`) must be **rethrown** by agents. These represent misconfigured platforms, auth errors, or retired model names that will repeat on every call. Swallowing them produces a false-negative SAFE result. `NonTransientLLMFailureException` (Infrastructure) extends `LLMProviderException` (Domain) so agents can catch the Domain type without importing Infrastructure.
- **A prompt the model cannot fit** (`LLMRequestTooLargeException`, never retried) is the one provider failure an agent recovers from: the chunk or review batch is split (`OversizedChunkRecovery`, `OversizedReviewBatchRecovery`) instead of rethrown. A batch client answers it per request with `LLMResponse::isRequestTooLarge()`. A single file the model cannot fit is recorded `errored`; `LLMFixedPromptTooLargeException` stops the run when the fixed part of the prompt is what leaves no room.
- **An answer with nothing usable in it is a degraded response, never a failure**: an output-limit cut-off, a content filter or an empty answer becomes an `LLMResponse` whose `isDegraded()` is true. It is never retried, never cached and never counted as a verdict. A new provider failure shape is classified in `TransientFailureClassifier` or `ConversionFailureExplainer`, never in an agent; every failed call the provider answered is booked against the budget (`DegradedAnswerBooker`).
- **A recording tool takes a call in or refuses it**: `RecordingToolInterface::RECORDED` answers a recorded call, any other answer is a refusal and records nothing. A chunk that ends on a refusal the model never repeated is recorded `errored` and left out of the cache.
- `VulnerabilityFactory::fromArray()` returns `null` on invalid data. `fromList()` silently drops nulls. Do not throw from the factory.
- **Structured collection seam**: with `audit.structured_collection: true` (default) the `record_vulnerability` tool's JSON Schema is the contract. To extend it, swap `RecordVulnerabilityToolFactoryInterface` at the composition root; do **not** add post-hoc validation in the agent.

How each of these mechanisms works, class by class: [`docs/architecture.md` → Provider failures and degraded answers](../../docs/architecture.md#provider-failures-and-degraded-answers).
