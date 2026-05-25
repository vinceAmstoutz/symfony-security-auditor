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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

/**
 * Typed representation of `symfony_security_auditor:` after Symfony's
 * TreeBuilder has validated and defaulted every key.
 *
 * Constructed once in `SymfonySecurityAuditorBundle::loadExtension()` so the
 * nested array-shape PHPDoc no longer doubles as the public configuration
 * contract — the VOs do. Downstream code that needs to introspect the
 * configuration (e.g. compiler passes) depends on these immutable types
 * instead of magic array keys.
 */
final readonly class BundleConfiguration
{
    public function __construct(
        public LLMConfiguration $llm,
        public ScanConfiguration $scan,
        public AuditExecutionConfiguration $audit,
        public RetryConfiguration $retry,
        public BudgetConfiguration $budget,
        public CacheConfiguration $cache,
        public RateLimitConfiguration $rateLimit,
    ) {}

    /**
     * @param array{
     *     model: string,
     *     attacker_model: string|null,
     *     reviewer_model: string|null,
     *     provider_json_mode?: bool,
     *     scan: array{included_paths: list<string>, respect_gitignore: bool, max_file_size_kb: int, secret_scrubbing: array{enabled: bool, additional_patterns: list<string>}},
     *     audit: array{max_iterations: int, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, max_tool_iterations: int, budget: array{max_tokens: int|null, max_cost_usd: float|null}, retry: array{max_attempts: int, initial_delay_ms: int, backoff_multiplier: float, jitter_ratio: float}, rate_limit: array{requests_per_minute: int|null, input_tokens_per_minute: int|null, output_tokens_per_minute: int|null}},
     *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
     * } $config
     */
    public static function fromArray(array $config): self
    {
        return new self(
            llm: new LLMConfiguration(
                model: $config['model'],
                attackerModelOverride: $config['attacker_model'],
                reviewerModelOverride: $config['reviewer_model'],
                providerJsonMode: $config['provider_json_mode'] ?? false,
            ),
            scan: new ScanConfiguration(
                includedPaths: $config['scan']['included_paths'],
                respectGitignore: $config['scan']['respect_gitignore'],
                maxFileSizeKb: $config['scan']['max_file_size_kb'],
                secretScrubbingEnabled: $config['scan']['secret_scrubbing']['enabled'],
                additionalScrubberPatterns: $config['scan']['secret_scrubbing']['additional_patterns'],
            ),
            audit: new AuditExecutionConfiguration(
                maxIterations: $config['audit']['max_iterations'],
                minConfidence: $config['audit']['min_confidence'],
                reviewerBatchSize: $config['audit']['reviewer_batch_size'],
                toolsEnabled: $config['audit']['tools_enabled'],
                maxToolIterations: $config['audit']['max_tool_iterations'],
            ),
            retry: new RetryConfiguration(
                maxAttempts: $config['audit']['retry']['max_attempts'],
                initialDelayMs: $config['audit']['retry']['initial_delay_ms'],
                backoffMultiplier: $config['audit']['retry']['backoff_multiplier'],
                jitterRatio: $config['audit']['retry']['jitter_ratio'],
            ),
            budget: new BudgetConfiguration(
                maxTokens: $config['audit']['budget']['max_tokens'],
                maxCostUsd: $config['audit']['budget']['max_cost_usd'],
            ),
            cache: new CacheConfiguration(
                enabled: $config['cache']['enabled'],
                dir: $config['cache']['dir'],
                promptCaching: $config['cache']['prompt_caching'],
            ),
            rateLimit: new RateLimitConfiguration(
                requestsPerMinute: $config['audit']['rate_limit']['requests_per_minute'],
                inputTokensPerMinute: $config['audit']['rate_limit']['input_tokens_per_minute'],
                outputTokensPerMinute: $config['audit']['rate_limit']['output_tokens_per_minute'],
            ),
        );
    }
}
