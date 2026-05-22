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
- `SymfonyAiLLMClient` is the only class that may import `symfony/ai`. It lives
  in Infrastructure and implements the Domain port.
- Swapping providers (Anthropic → OpenAI → Ollama) must require **zero code
  changes** — only `config/packages/ai.yaml`.
- `LLMResponse::parseJson()` strips markdown fences before decoding — always use
  it; never call `json_decode` directly on LLM output.
- LLM or JSON errors in agents must be **caught and logged**; return empty array
  / `reviewerValidated = false` rather than propagating.
- `VulnerabilityFactory::fromArray()` returns `null` on invalid data —
  `fromList()` silently drops nulls. Do not throw from the factory.
