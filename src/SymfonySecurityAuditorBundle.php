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
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
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
                ->booleanNode('provider_json_mode')
                    ->defaultFalse()
                    ->info('Opt into the provider-native JSON mode by sending `response_format: {type: json_object}` on every LLM call. Honored by OpenAI/Mistral/Ollama; silently ignored by Anthropic (which has no equivalent knob). Default false because behaviour is provider-dependent — only enable if your provider supports it. The prompt contract ("Return ONLY the JSON array") remains authoritative.')
                ->end()
                ->arrayNode('scan')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->arrayNode('included_paths')
                            ->info('Project-relative directories and files that define the scan surface. Defaults to the Symfony Flex skeleton (src/, config/, templates/, public/index.php). Anything outside this list is silently skipped — including ad-hoc root-level scripts, bin/, custom app/ or lib/ trees, and the build artefacts under var/, public/build, vendor/. Override for non-standard layouts; the audit only inspects what is listed here.')
                            ->scalarPrototype()->end()
                            ->defaultValue(ProjectFileScanner::DEFAULT_INCLUDED_PATHS)
                        ->end()
                        ->arrayNode('excluded_dirs')
                            ->info('Additional directories to exclude. Appended to hard defaults (vendor, node_modules, .git, .github, .idea, .vscode, var/cache, var/log, public/bundles, public/build, tests, Tests, migrations, Migrations, translations, build, coverage); never replaces them. Applied inside each included path — use this to prune sub-trees (e.g. src/Migrations) without rewriting the allow-list.')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
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
                            ->info('Give the attacker access to tools (read_file, grep, list_files, lookup_advisory) for cross-file investigation. Default true — without tools, lookup_advisory is dead weight and the attacker is blind across files. Costs more LLM round-trips per chunk; combine with cache.prompt_caching on Anthropic.')
                        ->end()
                        ->integerNode('max_tool_iterations')
                            ->defaultValue(AttackerAgent::DEFAULT_MAX_TOOL_ITERATIONS)
                            ->min(1)
                            ->info('Maximum tool-call rounds per chunk before forcing the attacker to commit to a final answer. Bounds runaway tool use.')
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
                            ->info('Opt into provider-side prompt caching by setting `cache_control: ephemeral` on every LLM call. Default true — honored by Anthropic for ~90% input-token discount; silently ignored by other providers (zero cost to leave on).')
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
     *     provider_json_mode: bool,
     *     scan: array{included_paths: list<string>, excluded_dirs: list<string>, respect_gitignore: bool, max_file_size_kb: int, secret_scrubbing: array{enabled: bool, additional_patterns: list<string>}},
     *     audit: array{max_iterations: int, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, max_tool_iterations: int, budget: array{max_tokens: int|null, max_cost_usd: float|null}, retry: array{max_attempts: int, initial_delay_ms: int, backoff_multiplier: float, jitter_ratio: float}, rate_limit: array{requests_per_minute: int|null, input_tokens_per_minute: int|null, output_tokens_per_minute: int|null}},
     *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
     * } $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        $builder->setParameter('symfony_security_auditor.attacker_model', $bundleConfiguration->llm->attackerModel());
        $builder->setParameter('symfony_security_auditor.reviewer_model', $bundleConfiguration->llm->reviewerModel());
        $builder->setParameter('symfony_security_auditor.scan.included_paths', $bundleConfiguration->scan->includedPaths);
        $builder->setParameter('symfony_security_auditor.scan.excluded_dirs', $bundleConfiguration->scan->excludedDirs);
        $builder->setParameter('symfony_security_auditor.scan.respect_gitignore', $bundleConfiguration->scan->respectGitignore);
        $builder->setParameter('symfony_security_auditor.scan.max_file_size_kb', $bundleConfiguration->scan->maxFileSizeKb);
        $builder->setParameter('symfony_security_auditor.scan.secret_scrubbing.enabled', $bundleConfiguration->scan->secretScrubbingEnabled);
        $builder->setParameter('symfony_security_auditor.scan.secret_scrubbing.additional_patterns', $bundleConfiguration->scan->additionalScrubberPatterns);
        $builder->setParameter('symfony_security_auditor.audit.max_iterations', $bundleConfiguration->audit->maxIterations);
        $builder->setParameter('symfony_security_auditor.audit.min_confidence', $bundleConfiguration->audit->minConfidence);
        $builder->setParameter('symfony_security_auditor.audit.reviewer_batch_size', $bundleConfiguration->audit->reviewerBatchSize);
        $builder->setParameter('symfony_security_auditor.audit.tools_enabled', $bundleConfiguration->audit->toolsEnabled);
        $builder->setParameter('symfony_security_auditor.audit.max_tool_iterations', $bundleConfiguration->audit->maxToolIterations);
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
            \sprintf('%s|prompt-v%d', $bundleConfiguration->llm->attackerModel(), AttackerPromptBuilder::PROMPT_VERSION),
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
            $services->set(ClockInterface::class, NativeClock::class)->private();
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
                $bundleConfiguration->cache->promptCaching,
                service(TokenUsageRecorder::class),
                service(RetryPolicy::class),
                service(TransientFailureClassifier::class),
                service(SleeperInterface::class),
                service(BudgetTracker::class),
                $bundleConfiguration->llm->providerJsonMode,
                service(RateLimiterInterface::class),
                service(TokenEstimatorInterface::class),
                service(RetryAfterHeaderParser::class),
            ]);

        $services->set('security_auditor.reviewer_client', SymfonyAiLLMClient::class)
            ->private()
            ->args([
                service(PlatformInterface::class),
                $bundleConfiguration->llm->reviewerModel(),
                service('logger'),
                SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                $bundleConfiguration->cache->promptCaching,
                service(TokenUsageRecorder::class),
                service(RetryPolicy::class),
                service(TransientFailureClassifier::class),
                service(SleeperInterface::class),
                service(BudgetTracker::class),
                $bundleConfiguration->llm->providerJsonMode,
                service(RateLimiterInterface::class),
                service(TokenEstimatorInterface::class),
                service(RetryAfterHeaderParser::class),
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
    }
}
