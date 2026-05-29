<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor;

use Psr\Clock\ClockInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class SymfonySecurityAuditorBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('model')
                    ->defaultValue('claude-opus-4-7')
                    ->info('Model name for both Attacker and Reviewer. Must be supported by the configured platform.')
                ->end()
                ->scalarNode('attacker_model')
                    ->defaultNull()
                    ->info('Override: dedicated model for the Attacker role. Falls back to `model` when null.')
                ->end()
                ->scalarNode('reviewer_model')
                    ->defaultNull()
                    ->info('Override: dedicated model for the Reviewer role. Falls back to `model` when null.')
                ->end()
                ->integerNode('max_output_tokens')
                    ->defaultValue(4096)
                    ->min(1)
                    ->info("Maximum output tokens per LLM call for both Attacker and Reviewer. Sets `max_tokens` in every platform request. Default 4096; symfony/ai's Anthropic bridge otherwise defaults to a much smaller value (~1000) that silently truncates findings.")
                ->end()
                ->integerNode('attacker_max_output_tokens')
                    ->defaultNull()
                    ->min(1)
                    ->info('Override: dedicated max output tokens for the Attacker role. Falls back to `max_output_tokens` when null. Useful when the attacker needs more headroom for detailed `record_vulnerability` tool-call arguments.')
                ->end()
                ->integerNode('reviewer_max_output_tokens')
                    ->defaultNull()
                    ->min(1)
                    ->info('Override: dedicated max output tokens for the Reviewer role. Falls back to `max_output_tokens` when null.')
                ->end()
                ->booleanNode('provider_json_mode')
                    ->defaultFalse()
                    ->info('Opt into the provider-native JSON mode by sending `response_format: {type: json_object}` on every LLM call. Honored by OpenAI/Mistral/Ollama; silently ignored by Anthropic (which has no equivalent knob). Default false because behaviour is provider-dependent — only enable if your provider supports it. The prompt contract ("Return ONLY the JSON array") remains authoritative.')
                ->end()
                ->arrayNode('scan')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->arrayNode('included_paths')
                            ->info('Project-relative directories and files that define the scan surface — the sole scoping knob. Defaults to the Symfony Flex skeleton (src/, config/, templates/, public/index.php). Anything outside this list is silently skipped, including vendor/, node_modules/, var/, tests/, migrations/, build artefacts, IDE folders, and any other top-level tree. Tighten or extend the list to match non-standard layouts; the audit only inspects what is listed here.')
                            ->scalarPrototype()->end()
                            ->defaultValue(ProjectFileScanner::DEFAULT_INCLUDED_PATHS)
                        ->end()
                        ->booleanNode('respect_gitignore')
                            ->defaultTrue()
                            ->info('When true, files ignored by the project .gitignore are excluded from the scan. Default true — matches the host project intent (committed code only) and avoids analyzing generated/cached artefacts. Set false for full-tree scans (rare).')
                        ->end()
                        ->integerNode('max_file_size_kb')
                            ->defaultValue(ProjectFileScanner::DEFAULT_MAX_FILE_SIZE_KB)
                            ->min(1)
                            ->info('Skip files larger than this size, in kilobytes.')
                        ->end()
                        ->arrayNode('custom_risk_patterns')
                            ->info('Project-specific risk markers merged into the deterministic pre-scanner. Keyed by file-type bucket (controller, voter, entity, repository, form, template, config, php, authenticator, messenger_handler, webhook_consumer, event_subscriber, normalizer, scheduler). Each entry is `<label>: { regex: <PCRE>, description: <human text> }`. Surface team idioms the built-in patterns do not know about (e.g. "must call AuditService::log() after every privileged action").')
                            ->useAttributeAsKey('bucket')
                            ->arrayPrototype()
                                ->useAttributeAsKey('label')
                                ->arrayPrototype()
                                    ->children()
                                        ->scalarNode('regex')->isRequired()->cannotBeEmpty()->info('PCRE pattern with delimiters, matched per-line against file content.')->end()
                                        ->scalarNode('description')->isRequired()->cannotBeEmpty()->info('Short human description rendered in the prompt next to the marker.')->end()
                                    ->end()
                                ->end()
                            ->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('secret_scrubbing')
                            ->addDefaultsIfNotSet()
                            ->info('Redact credential-shaped strings from file content before it reaches the LLM. Covers AWS/GitHub/Stripe/Slack/Google API keys, JWTs, PEM private keys, and env-style credential assignments.')
                            ->children()
                                ->booleanNode('enabled')
                                    ->defaultTrue()
                                    ->info('When true, file content is run through the configured scrubber before chunking. Default true — credentials in committed sample configs or .env.dist files would otherwise be sent verbatim to the LLM provider.')
                                ->end()
                                ->arrayNode('additional_patterns')
                                    ->info('Extra PCRE patterns merged with the defaults. Use to redact project-specific tokens (e.g. internal API keys).')
                                    ->scalarPrototype()->end()
                                    ->defaultValue([])
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('audit')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('max_iterations')
                            ->defaultValue(AuditOrchestrator::DEFAULT_MAX_ITERATIONS)
                            ->min(1)
                            ->info('Maximum number of attacker/reviewer iterations per audit.')
                        ->end()
                        ->floatNode('min_confidence')
                            ->defaultValue(AuditOrchestrator::DEFAULT_MIN_CONFIDENCE)
                            ->min(0.0)
                            ->max(1.0)
                            ->info('Minimum attacker self-reported confidence (0.0–1.0) required to forward a finding to the reviewer.')
                        ->end()
                        ->integerNode('reviewer_batch_size')
                            ->defaultValue(ReviewerAgent::DEFAULT_BATCH_SIZE)
                            ->min(1)
                            ->info('Number of findings reviewed per LLM call. 1 = one finding per call (highest precision, highest latency). Higher values reduce cost and latency at the risk of cross-talk between findings in the prompt.')
                        ->end()
                        ->booleanNode('tools_enabled')
                            ->defaultTrue()
                            ->info('Give the attacker access to tools (read_file, grep, list_files, lookup_advisory) for cross-file investigation. Default true — without tools, lookup_advisory is dead weight and the attacker is blind across files. Costs more LLM round-trips per chunk; combine with Anthropic prompt caching (`cache_retention` in `ai.yaml`) to offset the input-token cost.')
                        ->end()
                        ->booleanNode('structured_collection')
                            ->defaultTrue()
                            ->info("When true (default), the attacker emits findings by calling a schema-enforced `record_vulnerability` tool, one call per finding, instead of returning a JSON array. The platform validates each call against the tool's input schema, so malformed shapes (bare strings like \"dev\"/\"test\", wrapper objects like `{\"vulnerabilities\": [...]}` ) become structurally impossible. Works across every provider that supports tool use (Anthropic, OpenAI, Mistral, Ollama with tool-capable models). Set to false to fall back to the tightened JSON-array prompt path.")
                        ->end()
                        ->integerNode('max_tool_iterations')
                            ->defaultValue(AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS)
                            ->min(1)
                            ->info('Maximum tool-call rounds per chunk before forcing the attacker to commit to a final answer. Bounds runaway tool use.')
                        ->end()
                        ->booleanNode('reviewer_tools_enabled')
                            ->defaultFalse()
                            ->info('Give the reviewer access to the same tool registry the attacker uses, so it can verify cross-file context (parent-class guards, access_control rules, upstream sanitizers) instead of guessing from the Full File Context alone. Default false — adds round-trips per finding; opt-in for high-precision audits.')
                        ->end()
                        ->integerNode('reviewer_max_concurrent')
                            ->defaultValue(1)
                            ->min(1)
                            ->info('Maximum reviewer LLM calls resolved concurrently when reviewing one finding per call (reviewer_batch_size <= 1) with reviewer tools off. The reviewer phase is often half the audit wall-clock; setting this to 4-8 (within your provider rate limit) cuts it proportionally. Default 1 (sequential). Ignored when reviewer tools are enabled or the configured platform has no async transport.')
                        ->end()
                        ->integerNode('reviewer_max_tool_iterations')
                            ->defaultValue(ReviewerAgent::DEFAULT_MAX_TOOL_ITERATIONS)
                            ->min(1)
                            ->info("Maximum tool-call rounds per finding before forcing the reviewer to commit to a verdict. Lower default than the attacker because the reviewer's job is verification, not exploration.")
                        ->end()
                        ->arrayNode('static_prescan')
                            ->addDefaultsIfNotSet()
                            ->info('Deterministic zero-token risk-marker scan that runs before the LLM. Flags concrete locations (unserialize, |raw, csrf_protection: false, hardcoded secrets, Doctrine string concatenation, etc.) so the attacker prompt can focus on them. In lean mode, files with zero markers are skipped entirely — biggest token saver on large codebases.')
                            ->children()
                                ->booleanNode('enabled')
                                    ->defaultTrue()
                                    ->info('When true, every chunk is preceded by a "Pre-Scan Risk Markers" section in the user message. Default true — pure win on detection quality, zero token cost for the scan itself.')
                                ->end()
                                ->booleanNode('lean_mode')
                                    ->defaultFalse()
                                    ->info('When true, files with zero markers are dropped before the LLM ever sees them. Slashes token spend on real codebases (often 40-70%) at the cost of missing patterns the regex pre-scanner doesn\'t know about. Default false — opt-in for cost-sensitive runs.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('chunking')
                            ->addDefaultsIfNotSet()
                            ->info('How files are grouped into LLM calls. `feature` (default) packs a controller with its entity/repository/form/voter/templates so the LLM can follow cross-file data flow — the biggest detection-quality win. `type` keeps the legacy behaviour of sorting by attack-surface priority and slicing into fixed-size windows.')
                            ->children()
                                ->enumNode('strategy')
                                    ->values(['feature', 'type'])
                                    ->defaultValue('feature')
                                    ->info('Chunking strategy. `feature` colocates related files (UserController + User entity + UserRepository + …) in one chunk; `type` chunks by file-type priority. Default `feature`.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('escalation')
                            ->addDefaultsIfNotSet()
                            ->info('Two-pass attacker. A cheap-model sweep runs on every chunk; the expensive model only re-analyses files the cheap sweep flagged. Cuts attacker token spend ~3-5x on real projects where most files are inert, with detection quality close to running the expensive model on everything. Off by default — opt-in for cost-sensitive audits.')
                            ->children()
                                ->booleanNode('enabled')
                                    ->defaultFalse()
                                    ->info('When true, AttackerAgentInterface is wired to the EscalatingAttackerAgent wrapper. Requires `cheap_model` to be set.')
                                ->end()
                                ->scalarNode('cheap_model')
                                    ->defaultNull()
                                    ->info('Provider model id used for the cheap first pass (e.g. claude-haiku-4-5-20251001, gpt-5-mini, mistral-small). Falls back to the reviewer model when null.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('code_slicing')
                            ->addDefaultsIfNotSet()
                            ->info('Trim large PHP files down to security-relevant slices before they reach the LLM. The slicer keeps imports, attributes, class signatures, properties, and the FULL body of methods that touch security-relevant tokens (Request, Doctrine query builder, unserialize, shell exec, mailer, HttpClient, …). All other lines are replaced one-for-one with a `// elided` placeholder so line numbers stay accurate. Typical saving: 50-70% input tokens on controllers / services over 100 lines.')
                            ->children()
                                ->booleanNode('enabled')
                                    ->defaultFalse()
                                    ->info('When true, the configured CodeSlicerInterface runs over every chunked file. Default false — opt-in for cost-sensitive audits; smaller files and unfamiliar idioms keep more signal when sent unsliced.')
                                ->end()
                                ->integerNode('min_lines_before_slicing')
                                    ->defaultValue(80)
                                    ->min(10)
                                    ->info('Skip slicing for files shorter than this. Below ~80 lines the saving is not worth the missing context.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('poc_synthesis')
                            ->addDefaultsIfNotSet()
                            ->info('Optional follow-up stage that generates a concrete, copy-pasteable proof-of-concept (curl command, console invocation, payload body) for every validated finding at or above the configured severity floor. Spends extra LLM tokens per finding; off by default. Turn on when shipping reports to engineers who need actionable reproduction steps.')
                            ->children()
                                ->booleanNode('enabled')
                                    ->defaultFalse()
                                    ->info('When true, the PoCSynthesisStage runs after the audit and attaches a `synthesized_poc` field to qualifying findings. Default false.')
                                ->end()
                                ->enumNode('severity_floor')
                                    ->values(['critical', 'high', 'medium', 'low', 'info'])
                                    ->defaultValue('high')
                                    ->info('Minimum severity that triggers PoC synthesis. Default `high` — synthesize for critical+high only; medium and below keep the attacker\'s original proof string.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('budget')
                            ->addDefaultsIfNotSet()
                            ->info('Hard ceiling on cumulative LLM usage per audit run. Aborts the audit cleanly (exit code 2) with the partial report instead of running away on cost.')
                            ->children()
                                ->integerNode('max_tokens')
                                    ->defaultNull()
                                    ->min(1)
                                    ->info('Maximum total tokens (input + output, across attacker + reviewer) before the audit aborts. `null` (default) = unlimited.')
                                ->end()
                                ->floatNode('max_cost_usd')
                                    ->defaultNull()
                                    ->info('Maximum estimated cost (USD) before the audit aborts. Computed via the configured `PricingProviderInterface`. `null` (default) = unlimited.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('retry')
                            ->addDefaultsIfNotSet()
                            ->info('Bounded exponential-backoff retry around every LLM call. Transient failures (provider 429/5xx, network blips) are retried with jittered delays; non-transient failures (auth, validation) fail fast.')
                            ->children()
                                ->integerNode('max_attempts')
                                    ->defaultValue(RetryPolicy::DEFAULT_MAX_ATTEMPTS)
                                    ->min(1)
                                    ->info('Total attempts per LLM call, including the first try. `1` disables retries.')
                                ->end()
                                ->integerNode('initial_delay_ms')
                                    ->defaultValue(RetryPolicy::DEFAULT_INITIAL_DELAY_MS)
                                    ->min(0)
                                    ->info('Base delay (milliseconds) before the first retry. Subsequent retries multiply by `backoff_multiplier`.')
                                ->end()
                                ->floatNode('backoff_multiplier')
                                    ->defaultValue(RetryPolicy::DEFAULT_BACKOFF_MULTIPLIER)
                                    ->min(1.0)
                                    ->info('Exponential growth factor between retries. With initial 500ms and multiplier 2.0, retries wait ~500, ~1000, ~2000 ms.')
                                ->end()
                                ->floatNode('jitter_ratio')
                                    ->defaultValue(RetryPolicy::DEFAULT_JITTER_RATIO)
                                    ->min(0.0)
                                    ->max(1.0)
                                    ->info('Jitter applied to each computed delay, as a fraction in `[0.0, 1.0]`. `0.2` means each delay varies within ±20% of the base.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('rate_limit')
                            ->addDefaultsIfNotSet()
                            ->info('Proactive token-bucket throttle around every LLM call. Each dimension is independently nullable; when all three are `null` (the default) the bundle wires `NullRateLimiter` and behavior matches the pre-existing retry-only path. Configure the limits enforced by your provider tier (e.g. Anthropic RPM/ITPM/OTPM) to avoid hitting 429 in the first place — exhausted retries will still surface, but the steady-state path stays inside quota.')
                            ->children()
                                ->integerNode('requests_per_minute')
                                    ->defaultNull()
                                    ->min(1)
                                    ->info('Maximum LLM requests per minute. `null` (default) disables this dimension.')
                                ->end()
                                ->integerNode('input_tokens_per_minute')
                                    ->defaultNull()
                                    ->min(1)
                                    ->info('Maximum input tokens per minute. `null` (default) disables this dimension. A single request whose estimated input exceeds this cap throws `RateLimitRequestTooLargeException`.')
                                ->end()
                                ->integerNode('output_tokens_per_minute')
                                    ->defaultNull()
                                    ->min(1)
                                    ->info('Maximum output tokens per minute. `null` (default) disables this dimension. Counted post-hoc from `record()` so the next `acquire()` defers until the window resets when the bucket is full.')
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('cache')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultTrue()
                            ->info('Enable content-hash cache for attacker chunks. Skips the LLM call when an identical chunk has been analyzed before. Default true — huge cost saver on repeated runs (CI, PR scans).')
                        ->end()
                        ->scalarNode('dir')
                            ->defaultValue('%kernel.cache_dir%/symfony_security_auditor/attacker')
                            ->info('Filesystem path for the attacker cache. Created on first write.')
                        ->end()
                        ->booleanNode('prompt_caching')
                            ->defaultTrue()
                            ->setDeprecated(
                                'vinceamstoutz/symfony-security-auditor',
                                '1.7',
                                'The "%node%" option is deprecated and no longer has any effect. Prompt caching is controlled by your Symfony AI platform: set `cache_retention` (none|short|long) on the anthropic platform in `ai.yaml` (default `short` already enables it); OpenAI and Gemini cache automatically.',
                            )
                            ->info('Deprecated and ignored since 1.7. Prompt caching is configured on the Symfony AI platform, not here: set `cache_retention` (none|short|long) on the anthropic platform in `ai.yaml`. OpenAI and Gemini cache automatically.')
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;
    }

    /**
     * @param array{
     *     model: string,
     *     attacker_model: string|null,
     *     reviewer_model: string|null,
     *     max_output_tokens: int,
     *     attacker_max_output_tokens: int|null,
     *     reviewer_max_output_tokens: int|null,
     *     provider_json_mode: bool,
     *     scan: array{included_paths: list<string>, respect_gitignore: bool, max_file_size_kb: int, custom_risk_patterns: array<string, array<string, array{regex: string, description: string}>>, secret_scrubbing: array{enabled: bool, additional_patterns: list<string>}},
     *     audit: array{max_iterations: int, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, structured_collection?: bool, max_tool_iterations: int, reviewer_tools_enabled: bool, reviewer_max_tool_iterations: int, reviewer_max_concurrent: int, static_prescan: array{enabled: bool, lean_mode: bool}, chunking: array{strategy: string}, poc_synthesis: array{enabled: bool, severity_floor: string}, code_slicing: array{enabled: bool, min_lines_before_slicing: int}, escalation: array{enabled: bool, cheap_model: string|null}, budget: array{max_tokens: int|null, max_cost_usd: float|null}, retry: array{max_attempts: int, initial_delay_ms: int, backoff_multiplier: float, jitter_ratio: float}, rate_limit: array{requests_per_minute: int|null, input_tokens_per_minute: int|null, output_tokens_per_minute: int|null}},
     *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
     * } $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        $builder->setParameter('symfony_security_auditor.attacker_model', $bundleConfiguration->llm->attackerModel());
        $builder->setParameter('symfony_security_auditor.reviewer_model', $bundleConfiguration->llm->reviewerModel());
        $builder->setParameter('symfony_security_auditor.attacker_max_output_tokens', $bundleConfiguration->llm->attackerMaxOutputTokens());
        $builder->setParameter('symfony_security_auditor.reviewer_max_output_tokens', $bundleConfiguration->llm->reviewerMaxOutputTokens());
        $builder->setParameter('symfony_security_auditor.scan.included_paths', $bundleConfiguration->scan->includedPaths);
        $builder->setParameter('symfony_security_auditor.scan.respect_gitignore', $bundleConfiguration->scan->respectGitignore);
        $builder->setParameter('symfony_security_auditor.scan.max_file_size_kb', $bundleConfiguration->scan->maxFileSizeKb);
        $builder->setParameter('symfony_security_auditor.scan.secret_scrubbing.enabled', $bundleConfiguration->scan->secretScrubbingEnabled);
        $builder->setParameter('symfony_security_auditor.scan.secret_scrubbing.additional_patterns', $bundleConfiguration->scan->additionalScrubberPatterns);
        $builder->setParameter('symfony_security_auditor.scan.custom_risk_patterns', $bundleConfiguration->scan->customRiskPatterns);
        $builder->setParameter('symfony_security_auditor.audit.max_iterations', $bundleConfiguration->audit->maxIterations);
        $builder->setParameter('symfony_security_auditor.audit.min_confidence', $bundleConfiguration->audit->minConfidence);
        $builder->setParameter('symfony_security_auditor.audit.reviewer_batch_size', $bundleConfiguration->audit->reviewerBatchSize);
        $builder->setParameter('symfony_security_auditor.audit.tools_enabled', $bundleConfiguration->audit->toolsEnabled);
        $builder->setParameter('symfony_security_auditor.audit.structured_collection', $bundleConfiguration->audit->structuredCollection);
        $builder->setParameter('symfony_security_auditor.audit.max_tool_iterations', $bundleConfiguration->audit->maxToolIterations);
        $builder->setParameter('symfony_security_auditor.audit.reviewer_tools_enabled', $bundleConfiguration->audit->reviewerToolsEnabled);
        $builder->setParameter('symfony_security_auditor.audit.reviewer_max_tool_iterations', $bundleConfiguration->audit->reviewerMaxToolIterations);
        $builder->setParameter('symfony_security_auditor.audit.reviewer_max_concurrent', $bundleConfiguration->audit->reviewerMaxConcurrent);
        $builder->setParameter('symfony_security_auditor.audit.static_prescan.enabled', $bundleConfiguration->audit->staticPreScanEnabled);
        $builder->setParameter('symfony_security_auditor.audit.static_prescan.lean_mode', $bundleConfiguration->audit->staticPreScanLeanMode);
        $builder->setParameter('symfony_security_auditor.audit.chunking.strategy', $bundleConfiguration->audit->chunkingStrategy);
        $builder->setParameter('symfony_security_auditor.audit.poc_synthesis.enabled', $bundleConfiguration->audit->poCSynthesisEnabled);
        $builder->setParameter('symfony_security_auditor.audit.poc_synthesis.severity_floor', $bundleConfiguration->audit->poCSynthesisSeverityFloor);
        $builder->setParameter('symfony_security_auditor.audit.code_slicing.enabled', $bundleConfiguration->audit->codeSlicingEnabled);
        $builder->setParameter('symfony_security_auditor.audit.code_slicing.min_lines_before_slicing', $bundleConfiguration->audit->codeSlicingMinLines);
        $builder->setParameter('symfony_security_auditor.audit.budget.max_tokens', $bundleConfiguration->budget->maxTokens);
        $builder->setParameter('symfony_security_auditor.audit.budget.max_cost_usd', $bundleConfiguration->budget->maxCostUsd);
        $builder->setParameter('symfony_security_auditor.audit.retry.max_attempts', $bundleConfiguration->retry->maxAttempts);
        $builder->setParameter('symfony_security_auditor.audit.retry.initial_delay_ms', $bundleConfiguration->retry->initialDelayMs);
        $builder->setParameter('symfony_security_auditor.audit.retry.backoff_multiplier', $bundleConfiguration->retry->backoffMultiplier);
        $builder->setParameter('symfony_security_auditor.audit.retry.jitter_ratio', $bundleConfiguration->retry->jitterRatio);
        $builder->setParameter('symfony_security_auditor.cache.enabled', $bundleConfiguration->cache->enabled);
        $builder->setParameter('symfony_security_auditor.cache.dir', $bundleConfiguration->cache->dir);
        $builder->setParameter('symfony_security_auditor.cache.advisory_dir', $bundleConfiguration->cache->dir.'/advisory');
        $builder->setParameter('symfony_security_auditor.cache.prompt_caching', $bundleConfiguration->cache->promptCaching);
        $builder->setParameter(
            'symfony_security_auditor.cache.key_salt',
            \sprintf(
                '%s|prompt-v%d|prescan-v%d|patterns-%s',
                $bundleConfiguration->llm->attackerModel(),
                AttackerPromptBuilder::PROMPT_VERSION,
                RegexStaticPreScanner::CACHE_VERSION,
                substr(
                    hash(
                        'sha256',
                        json_encode($bundleConfiguration->scan->customRiskPatterns, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES),
                    ),
                    0,
                    16,
                ),
            ),
        );

        $services = $container->services();

        $maxTokens = $bundleConfiguration->budget->maxTokens;
        $maxCostUsd = $bundleConfiguration->budget->maxCostUsd;
        if (null === $maxTokens && null === $maxCostUsd) {
            $auditBudgetFactory = [AuditBudget::class, 'unlimited'];
            $auditBudgetArgs = [];
        } elseif (null !== $maxTokens && null !== $maxCostUsd) {
            $auditBudgetFactory = [AuditBudget::class, 'forBoth'];
            $auditBudgetArgs = [$maxTokens, $maxCostUsd];
        } elseif (null !== $maxTokens) {
            $auditBudgetFactory = [AuditBudget::class, 'forTokens'];
            $auditBudgetArgs = [$maxTokens];
        } else {
            $auditBudgetFactory = [AuditBudget::class, 'forCost'];
            $auditBudgetArgs = [$maxCostUsd];
        }

        $services->set(AuditBudget::class)
            ->private()
            ->factory($auditBudgetFactory)
            ->args($auditBudgetArgs);

        $services->set(NullRateLimiter::class)->private();

        if ($bundleConfiguration->rateLimit->isEnabled()) {
            $services->set(RateLimitConfiguration::class)
                ->private()
                ->args([
                    $bundleConfiguration->rateLimit->requestsPerMinute,
                    $bundleConfiguration->rateLimit->inputTokensPerMinute,
                    $bundleConfiguration->rateLimit->outputTokensPerMinute,
                ]);
            $services->set(TokenBucketRateLimiter::class)
                ->private()
                ->args([
                    service(RateLimitConfiguration::class),
                    service(ClockInterface::class),
                    service(SleeperInterface::class),
                ]);
            $services->alias(RateLimiterInterface::class, TokenBucketRateLimiter::class);
        } else {
            $services->alias(RateLimiterInterface::class, NullRateLimiter::class);
        }

        $services->set(RetryAfterHeaderParser::class)->private();

        $services->set('security_auditor.attacker_client', SymfonyAiLLMClient::class)
            ->private()
            ->args([
                service(PlatformInterface::class),
                $bundleConfiguration->llm->attackerModel(),
                service('logger'),
                SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                service(TokenUsageRecorder::class),
                service(RetryPolicy::class),
                service(TransientFailureClassifier::class),
                service(SleeperInterface::class),
                service(BudgetTracker::class),
                $bundleConfiguration->llm->providerJsonMode,
                service(RateLimiterInterface::class),
                service(TokenEstimatorInterface::class),
                service(RetryAfterHeaderParser::class),
                $bundleConfiguration->llm->attackerMaxOutputTokens(),
            ]);

        $services->set('security_auditor.reviewer_client', SymfonyAiLLMClient::class)
            ->private()
            ->args([
                service(PlatformInterface::class),
                $bundleConfiguration->llm->reviewerModel(),
                service('logger'),
                SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                service(TokenUsageRecorder::class),
                service(RetryPolicy::class),
                service(TransientFailureClassifier::class),
                service(SleeperInterface::class),
                service(BudgetTracker::class),
                $bundleConfiguration->llm->providerJsonMode,
                service(RateLimiterInterface::class),
                service(TokenEstimatorInterface::class),
                service(RetryAfterHeaderParser::class),
                $bundleConfiguration->llm->reviewerMaxOutputTokens(),
            ]);

        $services->alias(LLMClientInterface::class, 'security_auditor.attacker_client');

        $cacheServiceId = $bundleConfiguration->cache->enabled
            ? FilesystemAttackerCache::class
            : NullAttackerCache::class;
        $services->alias(AttackerCacheInterface::class, $cacheServiceId);

        $scrubberServiceId = $bundleConfiguration->scan->secretScrubbingEnabled
            ? RegexSecretScrubber::class
            : NullSecretScrubber::class;
        $services->alias(SecretScrubberInterface::class, $scrubberServiceId);

        $services->alias(AdvisoryDatabaseInterface::class, ComposerAuditAdvisoryDatabase::class);

        $preScannerServiceId = $bundleConfiguration->audit->staticPreScanEnabled
            ? RegexStaticPreScanner::class
            : NullStaticPreScanner::class;
        $services->alias(StaticPreScannerInterface::class, $preScannerServiceId);

        $codeSlicerServiceId = $bundleConfiguration->audit->codeSlicingEnabled
            ? RegexCodeSlicer::class
            : NullCodeSlicer::class;
        $services->alias(CodeSlicerInterface::class, $codeSlicerServiceId);

        if ($bundleConfiguration->audit->escalationEnabled) {
            $cheapModel = $bundleConfiguration->audit->escalationCheapModel ?? $bundleConfiguration->llm->reviewerModel();

            $services->set('security_auditor.cheap_attacker_client', SymfonyAiLLMClient::class)
                ->private()
                ->args([
                    service(PlatformInterface::class),
                    $cheapModel,
                    service('logger'),
                    SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                    service(TokenUsageRecorder::class),
                    service(RetryPolicy::class),
                    service(TransientFailureClassifier::class),
                    service(SleeperInterface::class),
                    service(BudgetTracker::class),
                    $bundleConfiguration->llm->providerJsonMode,
                    service(RateLimiterInterface::class),
                    service(TokenEstimatorInterface::class),
                    service(RetryAfterHeaderParser::class),
                    $bundleConfiguration->llm->attackerMaxOutputTokens(),
                ]);

            $services->set('security_auditor.cheap_attacker', AttackerAgent::class)
                ->private()
                ->args([
                    service('security_auditor.cheap_attacker_client'),
                    service(AttackerPromptBuilderInterface::class),
                    service(VulnerabilityFactory::class),
                    service(AttackerCacheInterface::class),
                    service('logger'),
                    service(ToolRegistryFactoryInterface::class),
                    $bundleConfiguration->audit->toolsEnabled,
                    $bundleConfiguration->audit->maxToolIterations,
                    service(StaticPreScannerInterface::class),
                    $bundleConfiguration->audit->staticPreScanLeanMode,
                    service(FileChunker::class),
                    service(CodeSlicerInterface::class),
                    null,
                    service(RecordVulnerabilityToolFactoryInterface::class),
                    $bundleConfiguration->audit->structuredCollection,
                ]);

            $services->set(EscalatingAttackerAgent::class)
                ->private()
                ->args([
                    service('security_auditor.cheap_attacker'),
                    service(AttackerAgent::class),
                    service('logger'),
                ]);

            $services->alias(AttackerAgentInterface::class, EscalatingAttackerAgent::class);
        }
    }
}
