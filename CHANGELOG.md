# Changelog

All notable changes to `vinceamstoutz/symfony-security-auditor` are documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org). See
[`docs/versioning.md`](docs/versioning.md) for the backward compatibility policy
— what is public API, what is internal, and how deprecations are handled.

## [Unreleased]

## [1.0.0]

First stable release.

### Added

- Multi-agent security audit pipeline: **Ingestion → Mapping → Audit**, driven
  by an adversarial **Attacker** agent and a skeptical **Reviewer** agent (up to
  3 iterations, stops early when no new findings emerge).
- Provider-agnostic LLM backend via
  [`symfony/ai`](https://symfony.com/doc/current/ai/index.html): works out of
  the box with Anthropic (Claude), OpenAI, Azure OpenAI, Google Gemini, Google
  Vertex AI, AWS Bedrock, DeepSeek, Mistral, Meta (Llama), and Ollama (local).
  Swapping providers requires only `config/packages/ai.yaml` changes.
- Symfony Console command `audit:run` with three output formats:
  - `console` — human-readable summary.
  - `json` — machine-readable report.
  - `sarif` — SARIF 2.1.0 for GitHub Code Scanning and GitLab Security
    Dashboard. The driver `version` is sourced dynamically from the installed
    Composer metadata.
- Cross-file investigation tools available to the Attacker agent: `read_file`,
  `grep`, `list_files`, and `lookup_advisory` (live CVE feed backed by
  `composer audit`).
- Split-model support — pair a larger model for attack discovery with a faster,
  cheaper model for review (e.g. Claude Opus + Claude Haiku).
- Content-hash filesystem cache for attacker chunks (skip identical re-analyses)
  and opt-in provider-side prompt caching (`cache_control: ephemeral` — honored
  by Anthropic, ignored by others).
- 32 vulnerability types across 6 OWASP-aligned categories (Injection, Broken
  Access Control, Logic Flaws, Symfony-specific, Data Exposure, Cryptographic).
- Documented extension points: `LLMClientInterface`,
  `AdvisoryDatabaseInterface`, `AttackerPromptBuilderInterface`,
  `ReviewerPromptBuilderInterface`, `ProjectFileScannerInterface`,
  `AttackerCacheInterface`, `ToolInterface`, `PipelineInterface`,
  `StageInterface`.
- Documentation: configuration reference, architecture overview, CI integration
  guide, extension guide, FAQ, troubleshooting, and a backward compatibility /
  SemVer policy in `docs/versioning.md`.
- Example configurations and an intentionally-vulnerable Symfony skeleton under
  `examples/` for end-to-end demonstrations.

### Notes

- Default model is `claude-opus-4-5` to match the documented Quick Start.
  Configure another model via `model:`, `attacker_model:`, or `reviewer_model:`.
- Bundle services register in `dev` and `test` environments only by default (per
  `config/bundles.php` guidance in the README).
