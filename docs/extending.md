# Extending symfony-security-auditor

All extension points are PHP interfaces. Wire your implementations via
`config/services.yaml`; no bundle internals need to be modified.

## Table of Contents

- [1. Custom LLM Client](#1-custom-llm-client)
- [2. Custom Pipeline Stage](#2-custom-pipeline-stage)
- [3. Custom Agent (Attacker or Reviewer)](#3-custom-agent-attacker-or-reviewer)
- [4. Custom Report Output](#4-custom-report-output)
- [5. Other Pluggable Ports](#5-other-pluggable-ports)
- [6. Schema-Enforced Collection (`audit.structured_collection`)](#6-schema-enforced-collection-auditstructured_collection)

> See also: [Architecture](architecture.md) · [Configuration](configuration.md)
> · [FAQ](faq.md) · [Troubleshooting](troubleshooting.md)

---

## 1. Custom LLM Client

**Interface**:
`VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface`

```php
interface LLMClientInterface
{
    public function complete(string $systemPrompt, string $userMessage): LLMResponse;

    public function completeWithTools(
        string $systemPrompt,
        string $userMessage,
        ToolRegistry $toolRegistry,
        int $maxToolIterations,
    ): LLMResponse;

    public function model(): string;
}
```

`completeWithTools()` drives an autonomous tool-using conversation: as long as
the model emits tool calls (and the iteration cap is not reached), the client
executes them via the supplied `ToolRegistry` (also under
`Audit\Domain\Port\Tool\`) and feeds the results back. Stub implementations may
delegate to `complete()` when they don't need tool support.

The default implementation (`SymfonyAiLLMClient`) delegates to `symfony/ai`'s
`AgentInterface`. Replace it when you need direct HTTP calls, custom retry
logic, token tracking, or a provider that `symfony/ai` does not support.

`LLMResponse` is an immutable value object built via its `of()` factory, with
the token counts grouped into a `TokenUsageSnapshot`:

```php
LLMResponse::of(
    content: string,      // raw text from the model
    model: string,
    stopReason: string,
    usage: TokenUsageSnapshot::of(inputTokens: int, outputTokens: int),
);
```

> The legacy
> `LLMResponse::create(content, inputTokens, outputTokens, model, stopReason)`
> factory is **deprecated since 1.13** and removed in the next `MAJOR`; use
> `of()` in new code.

Key read methods: `content()`, `parseJson(): array` (strips markdown fences then
JSON-decodes), `isEmpty(): bool`, `totalTokens(): int`.

### Implementation

```php
// src/Llm/AcmeLlmClient.php
namespace App\Llm;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

final class AcmeLlmClient implements LLMClientInterface
{
    public function __construct(
        private readonly \Symfony\Contracts\HttpClient\HttpClientInterface $http,
        private readonly string $apiKey,
    ) {}

    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        $response = $this->http->request('POST', 'https://api.acme.ai/v1/complete', [
            'headers' => ['Authorization' => 'Bearer ' . $this->apiKey],
            'json' => [
                'system' => $systemPrompt,
                'user'   => $userMessage,
                'model'  => $this->model(),
            ],
        ])->toArray();

        return LLMResponse::of(
            content:    $response['choices'][0]['text'],
            model:      $this->model(),
            stopReason: $response['choices'][0]['finish_reason'],
            usage:      TokenUsageSnapshot::of(
                inputTokens:  $response['usage']['prompt_tokens'],
                outputTokens: $response['usage']['completion_tokens'],
            ),
        );
    }

    public function completeWithTools(
        string $systemPrompt,
        string $userMessage,
        ToolRegistry $toolRegistry,
        int $maxToolIterations,
    ): LLMResponse {
        // Simplest stub: ignore tools and delegate to single-shot completion.
        return $this->complete($systemPrompt, $userMessage);
    }

    public function model(): string
    {
        return 'acme-secure-v2';
    }
}
```

### Wire

The bundle registers two named clients (`security_auditor.attacker_client` and
`security_auditor.reviewer_client`) that are injected into `AttackerAgent` and
`ReviewerAgent` directly. To replace both with your client, alias the interface
and override those two arguments:

```yaml
# config/services.yaml
App\Llm\AcmeLlmClient:
    arguments:
        $apiKey: '%env(ACME_API_KEY)%'

security_auditor.attacker_client:
    alias: App\Llm\AcmeLlmClient
    public: true

security_auditor.reviewer_client:
    alias: App\Llm\AcmeLlmClient
    public: true
```

To replace the client for every consumer that type-hints `LLMClientInterface`
directly:

```yaml
VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface:
    alias: App\Llm\AcmeLlmClient
```

---

## 2. Custom Pipeline Stage

**Interface**:
`VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface`

```php
interface StageInterface
{
    public function process(AuditContext $context): void;
    public function name(): string;
}
```

`AuditContext` is the mutable bag that flows through every stage. Relevant API:

| Method                                                     | Effect                                     |
| ---------------------------------------------------------- | ------------------------------------------ |
| `projectPath(): string`                                    | read-only — set at construction            |
| `auditId(): string`                                        | read-only                                  |
| `projectFiles(): list<ProjectFile>`                        | files collected by `IngestionStage`        |
| `setProjectFiles(array $files): void`                      | replace the file list                      |
| `mapping(): SymfonyMapping\|null`                          | routing/controller map from `MappingStage` |
| `setMapping(SymfonyMapping $m): void`                      | set or replace the mapping                 |
| `vulnerabilities(): array<string, Vulnerability>`          | keyed by id                                |
| `addVulnerability(Vulnerability $v): void`                 | add a new finding                          |
| `replaceVulnerability(Vulnerability $v): void`             | overwrite an existing id                   |
| `validatedVulnerabilities(): array<string, Vulnerability>` | reviewer-validated subset                  |
| `setMeta(string $key, mixed $value): void`                 | arbitrary stage-to-stage data              |
| `getMeta(string $key, mixed $default = null): mixed`       | read stage metadata                        |

### Implementation — deduplication stage

```php
// src/Pipeline/Stage/DeduplicationStage.php
namespace App\Pipeline\Stage;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

final class DeduplicationStage implements StageInterface
{
    public function name(): string
    {
        return 'deduplication';
    }

    public function process(AuditContext $context): void
    {
        $seen = [];

        foreach ($context->vulnerabilities() as $id => $vuln) {
            $key = $vuln->filePath() . ':' . $vuln->lineStart() . ':' . $vuln->type()->value;

            if (array_key_exists($key, $seen)) {
                // Keep the one with higher confidence; replace lower-confidence duplicate.
                $existing = $context->vulnerabilities()[$seen[$key]];
                if ($vuln->confidence() > $existing->confidence()) {
                    $context->replaceVulnerability($vuln);
                    $seen[$key] = $id;
                }
                // Drop the current entry — no API to remove, so overwrite with the winner.
                continue;
            }

            $seen[$key] = $id;
        }
    }
}
```

> `AuditContext` has no `removeVulnerability()` method. If your stage needs to
> filter findings, collect the survivors and call `replaceVulnerability()` for
> each, or store a skip-list in metadata with `setMeta()` for a downstream
> consumer.

### Wire — append after AuditStage

`AuditPipeline` collects stages via the
`symfony_security_auditor.pipeline_stage` tag. Anything implementing
`StageInterface` is auto-tagged in `config/services.php`, so a service
definition is enough — order follows service registration.

```yaml
# config/services.yaml
services:
    App\Pipeline\Stage\DeduplicationStage: ~
```

If you need to override the order, manually tag with `priority`:

```yaml
services:
    App\Pipeline\Stage\DeduplicationStage:
        tags:
            - { name: symfony_security_auditor.pipeline_stage, priority: -100 }
```

---

## 3. Custom Agent (Attacker or Reviewer)

### AttackerAgentInterface

**Interface**:
`VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface`

```php
interface AttackerAgentInterface
{
    /** @param ProjectFile[] $files */
    public function analyze(array $files, SymfonyMapping $mapping): array; // Vulnerability[]
}
```

The attacker receives all ingested `ProjectFile` objects and the Symfony
route/controller mapping, then returns raw `Vulnerability` instances. Use
`VulnerabilityFactory` to convert LLM JSON arrays into validated domain objects
— invalid or incomplete shapes are silently dropped.

```php
// src/Agent/RuleBasedAttackerAgent.php
namespace App\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

final class RuleBasedAttackerAgent implements AttackerAgentInterface
{
    public function __construct(
        private readonly LLMClientInterface $llmClient,
        private readonly VulnerabilityFactory $factory,
    ) {}

    public function analyze(array $files, SymfonyMapping $mapping): array
    {
        $combined = implode("\n\n", array_map(
            static fn(ProjectFile $f): string => "// {$f->relativePath()}\n{$f->content()}",
            $files,
        ));

        $response = $this->llmClient->complete(
            systemPrompt: $this->systemPrompt(),
            userMessage: $combined,
        );

        if ($response->isEmpty()) {
            return [];
        }

        return $this->factory->fromList($response->parseJson())->vulnerabilities();
    }

    private function systemPrompt(): string
    {
        return <<<PROMPT
            You are a security auditor. Return a JSON array of vulnerability objects.
            Each object must have: type, severity, title, description, file_path,
            line_start, line_end, vulnerable_code, attack_vector, proof, remediation, confidence.
            Valid type values: sql_injection, command_injection, broken_access_control, ...
            Valid severity values: critical, high, medium, low, info.
            Confidence is a float between 0.0 and 1.0.
            PROMPT;
    }
}
```

Wire:

```yaml
# config/services.yaml
App\Agent\RuleBasedAttackerAgent: ~

VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface:
    alias: App\Agent\RuleBasedAttackerAgent
```

### ReviewerAgentInterface

**Interface**:
`VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface`

```php
interface ReviewerAgentInterface
{
    /** @param Vulnerability[] $vulnerabilities  @param ProjectFile[] $projectFiles */
    public function review(array $vulnerabilities, array $projectFiles): array; // Vulnerability[]
}
```

The reviewer receives findings from the attacker plus the full file list for
cross-referencing. Return the same or modified `Vulnerability` objects. Use
`$vulnerability->withReviewerValidation(true)` to mark a finding as confirmed —
only validated findings appear in the final `AuditReport`. Use
`$vulnerability->withElevatedSeverity(VulnerabilitySeverity::CRITICAL)` to
adjust severity before returning.

```php
// src/Agent/StrictReviewerAgent.php
namespace App\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;

final class StrictReviewerAgent implements ReviewerAgentInterface
{
    public function review(array $vulnerabilities, array $projectFiles): array
    {
        $reviewed = [];

        foreach ($vulnerabilities as $vuln) {
            // Only validate findings with confidence >= 0.7.
            if ($vuln->confidence() < 0.7) {
                $reviewed[] = $vuln->withReviewerValidation(false);
                continue;
            }

            $validated = $vuln->withReviewerValidation(true);

            // Escalate any unreviewed HIGH to CRITICAL when confidence is perfect.
            if ($vuln->severity() === VulnerabilitySeverity::HIGH && $vuln->confidence() === 1.0) {
                $validated = $validated->withElevatedSeverity(VulnerabilitySeverity::CRITICAL);
            }

            $reviewed[] = $validated;
        }

        return $reviewed;
    }
}
```

Wire:

```yaml
VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface:
    alias: App\Agent\StrictReviewerAgent
```

### VulnerabilityFactory

`VulnerabilityFactory` is a service (autowired). Inject it wherever you need to
convert raw LLM arrays into domain objects.

```php
// $rawList is the decoded JSON array from the LLM.
$result = $this->factory->fromList($rawList); // VulnerabilityHydrationResult

$vulnerabilities = $result->vulnerabilities(); // list<Vulnerability>
$result->totalDropped();                       // int — entries the factory dropped
$result->droppedBy(VulnerabilityDropReason::HYDRATION_FAILED); // per-reason count
```

`fromList()` calls `fromArray()` per item and drops any entry that fails
validation (unknown `type`/`severity` enum value, empty `title`,
`line_end < line_start`, `confidence` outside `[0.0, 1.0]`). Each drop is logged
at `warning` level with a structured `reason` code
(`VulnerabilityDropReason::NON_ARRAY_ENTRY` for non-array entries,
`VulnerabilityDropReason::HYDRATION_FAILED` for invalid shapes) and aggregated
in the returned `VulnerabilityHydrationResult` so callers can surface drop
counts in their reports or metrics.

---

## 4. Custom Report Output

`AuditReport` is produced by `AuditReport::fromContext(AuditContext $context)`
at the end of the pipeline. It contains only reviewer-validated vulnerabilities.

Available read methods:

```php
$report->auditId(): string
$report->projectPath(): string
$report->startedAt(): \DateTimeImmutable
$report->completedAt(): \DateTimeImmutable
$report->durationSeconds(): float
$report->filesScanned(): int
$report->cost(): AuditCost                           // tokens + estimated USD
$report->coverage(): array<string, mixed>            // per-file coverage metadata
$report->vulnerabilities(): list<Vulnerability>      // validated only
$report->totalVulnerabilities(): int
$report->vulnerabilitiesBySeverity(VulnerabilitySeverity $s): list<Vulnerability>
$report->vulnerabilitiesByType(VulnerabilityType $t): list<Vulnerability>
$report->riskScore(): int                            // sum of severity scores
$report->riskLevel(): string                         // SAFE|LOW|MEDIUM|HIGH|CRITICAL
$report->toArray(): array<string, mixed>             // fully serializable; includes 'cost' key
```

`Vulnerability::toArray()` keys: `id`, `type`, `category`, `owasp`, `severity`,
`severity_score`, `title`, `description`, `file`, `line_start`, `line_end`,
`vulnerable_code`, `attack_vector`, `proof`, `remediation`, `confidence`,
`reviewer_validated`, `detected_at`, `synthesized_poc`.

### Built-in formats

`ReportRenderer` ships three formats out of the box:

- `renderConsole(AuditReport): string` — human-readable terminal output
  (templates in `Report/Template/*.txt`).
- `renderJson(AuditReport): string` — pretty-printed `AuditReport::toArray()`.
- `renderSarif(AuditReport): string` — SARIF 2.1.0, consumable by GitHub Code
  Scanning and GitLab Security Dashboard.

Trigger them via `audit:run --format=console|json|sarif` (see [`ci.md`](ci.md)
for SARIF upload workflows).

### Adding a new format

1. Add a case to `Command\OutputFormat`.
2. Add a `render<Name>(AuditReport): string` method to `ReportRenderer`.
3. Add the matching arm to the `match` block in `Command\ReportWriter::write()`.

`AuditReport` is a plain value object — once the pipeline completes you may also
inject it directly into any consumer (custom command, controller, event
listener) and serialize it however fits your output target without going through
`ReportRenderer`.

---

## 5. Other Pluggable Ports

Beyond the seams above, these Domain ports can each be implemented and aliased
in `config/services.yaml` to override the bundled behaviour (see
[`docs/versioning.md`](versioning.md) for the full BC-protected list):

- `StaticPreScannerInterface` — supply your own deterministic risk-marker scan
  (default: `RegexStaticPreScanner`, or set
  `audit.static_prescan.enabled: false` for the null scanner). Project-specific
  markers can also be added without a new class via `scan.custom_risk_patterns`.
- `CodeSlicerInterface` — control how files are trimmed before the LLM (default:
  `NullCodeSlicer`; enable the bundled `RegexCodeSlicer` with
  `audit.code_slicing.enabled: true`).
- `GitChangedFilesResolverInterface` — change how `--since` resolves the
  changed-file set (default: `ProcessGitChangedFilesResolver`, backed by
  `git diff`).
- `BatchCapableLLMClientInterface` — an opt-in extension of `LLMClientInterface`
  for clients that resolve several prompts concurrently; the reviewer uses it
  when `audit.reviewer_max_concurrent > 1`.
- `RecordVulnerabilityToolFactoryInterface` — builds the schema-enforced tool
  used in `audit.structured_collection` mode (default:
  `RecordVulnerabilityToolFactory` returning `RecordVulnerabilityTool`). Swap
  the factory if you want to enrich the tool's schema (extra fields, tighter
  enums) without forking the agent — every provider that supports tool use will
  validate calls against the schema you publish.

## 6. Schema-Enforced Collection (`audit.structured_collection`)

By default (`audit.structured_collection: true`), the attacker is given a
`record_vulnerability` tool with a strict JSON-Schema input and the prompt
instructs it to make one tool call per finding. The provider validates each call
against the schema before the agent ever sees it, so bare strings, wrapper
objects, and missing required fields are structurally impossible.

Setting `audit.structured_collection: false` falls back to the legacy JSON-array
prompt path. The tightened prompt still forbids the common drift shapes
(`["dev", "test", {...}]`, `{"vulnerabilities": [...]}`), but enforcement is
then prompt-based rather than schema-based — keep this fallback for models
without tool-use support or when you specifically want the JSON path.

Internals:

- `RecordVulnerabilityTool` (Infrastructure) implements the Domain port
  `ToolInterface`; its `parametersSchema` mirrors the `Vulnerability` shape and
  enumerates `VulnerabilityType::cases()` / `VulnerabilitySeverity::cases()`, so
  adding a new case in Domain auto-propagates to the tool.
- `VulnerabilityCollector` (Application) accumulates the validated payloads
  during the conversation and is drained by `AttackerAgent` after each chunk.
- `RecordVulnerabilityToolFactoryInterface` (Application) is the seam if you
  want to publish a richer schema.

Provider coverage:

| Provider  | Tool input validation                                      |
| --------- | ---------------------------------------------------------- |
| Anthropic | Strict — already used by the agent for investigation tools |
| OpenAI    | Strict (`strict: true`)                                    |
| Mistral   | Validated                                                  |
| Ollama    | Validated, only on tool-capable models                     |

When the flag is off, the JSON-array path runs with the tightened prompt that
forbids object wrappers and env-name array elements — that path remains the
safety net for environments without provider-side tool validation.
