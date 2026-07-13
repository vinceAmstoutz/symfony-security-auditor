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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditExecutionConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;

/**
 * Typed representation of `symfony_security_auditor:` after Symfony's
 * TreeBuilder has validated and defaulted every key.
 *
 * Constructed once in `SymfonySecurityAuditorBundle::loadExtension()` so the
 * nested array-shape PHPDoc no longer doubles as the public configuration
 * contract — the VOs do. Downstream code that needs to introspect the
 * configuration (e.g. compiler passes) depends on these immutable types
 * instead of magic array keys.
 *
 * @phpstan-type BundleConfigArray array{
 *     profile?: string,
 *     model: string,
 *     attacker_model: string|null,
 *     reviewer_model: string|null,
 *     max_output_tokens?: int,
 *     attacker_max_output_tokens?: int|null,
 *     reviewer_max_output_tokens?: int|null,
 *     provider_json_mode?: bool,
 *     scan: array{included_paths: list<string>, respect_gitignore: bool, max_file_size_kb: int, import_sarif?: list<string>, custom_risk_patterns: array<string, array<string, array{regex: string, description: string}>>, secret_scrubbing: array{enabled: bool, additional_patterns: list<string>}},
 *     audit: array{max_iterations: int|null, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, structured_collection?: bool, reviewer_structured_collection?: bool, stable_system_prompt?: bool, max_tool_iterations: int, reviewer_tools_enabled: bool, reviewer_max_tool_iterations: int, baseline?: string|null, fail_on?: string, excluded_types?: list<string>, included_types?: list<string>, reviewer_max_concurrent: int|null, attacker_max_concurrent: int|null, static_prescan: array{enabled: bool, lean_mode: bool|null}, chunking: array{strategy: string}, poc_synthesis: array{enabled: bool|null, severity_floor: string}, code_slicing: array{enabled: bool|null, min_lines_before_slicing: int}, escalation: array{enabled: bool, cheap_model: string|null}, budget: array{max_tokens: int|null, max_cost_usd: float|null}, retry: array{max_attempts: int, initial_delay_ms: int, backoff_multiplier: float, jitter_ratio: float}, rate_limit: array{requests_per_minute: int|null, input_tokens_per_minute: int|null, output_tokens_per_minute: int|null}},
 *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
 * }
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
     * @param BundleConfigArray $config
     *
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    public static function fromArray(array $config): self
    {
        $auditProfile = AuditProfile::from($config['profile'] ?? 'balanced');

        return new self(
            llm: new LLMConfiguration(
                model: $config['model'],
                attackerModelOverride: $config['attacker_model'],
                reviewerModelOverride: $config['reviewer_model'],
                maxOutputTokens: $config['max_output_tokens'] ?? 4096,
                attackerMaxOutputTokensOverride: $config['attacker_max_output_tokens'] ?? null,
                reviewerMaxOutputTokensOverride: $config['reviewer_max_output_tokens'] ?? null,
                providerJsonMode: $config['provider_json_mode'] ?? false,
            ),
            scan: new ScanConfiguration(
                includedPaths: $config['scan']['included_paths'],
                respectGitignore: $config['scan']['respect_gitignore'],
                maxFileSizeKb: $config['scan']['max_file_size_kb'],
                secretScrubbingEnabled: $config['scan']['secret_scrubbing']['enabled'],
                additionalScrubberPatterns: $config['scan']['secret_scrubbing']['additional_patterns'],
                customRiskPatterns: $config['scan']['custom_risk_patterns'],
                importSarifPaths: $config['scan']['import_sarif'] ?? [],
            ),
            audit: new AuditExecutionConfiguration(
                maxIterations: $config['audit']['max_iterations'] ?? $auditProfile->maxIterations(),
                minConfidence: $config['audit']['min_confidence'],
                reviewerBatchSize: $config['audit']['reviewer_batch_size'],
                toolsEnabled: $config['audit']['tools_enabled'],
                maxToolIterations: $config['audit']['max_tool_iterations'],
                staticPreScanEnabled: $config['audit']['static_prescan']['enabled'],
                staticPreScanLeanMode: $config['audit']['static_prescan']['lean_mode'] ?? $auditProfile->staticPreScanLeanMode(),
                reviewerToolsEnabled: $config['audit']['reviewer_tools_enabled'],
                reviewerMaxToolIterations: $config['audit']['reviewer_max_tool_iterations'],
                reviewerMaxConcurrent: $config['audit']['reviewer_max_concurrent'] ?? $auditProfile->reviewerMaxConcurrent(),
                attackerMaxConcurrent: $config['audit']['attacker_max_concurrent'] ?? $auditProfile->attackerMaxConcurrent(),
                chunkingStrategy: $config['audit']['chunking']['strategy'],
                poCSynthesisEnabled: $config['audit']['poc_synthesis']['enabled'] ?? $auditProfile->poCSynthesisEnabled(),
                poCSynthesisSeverityFloor: $config['audit']['poc_synthesis']['severity_floor'],
                codeSlicingEnabled: $config['audit']['code_slicing']['enabled'] ?? $auditProfile->codeSlicingEnabled(),
                codeSlicingMinLines: $config['audit']['code_slicing']['min_lines_before_slicing'],
                escalationEnabled: $config['audit']['escalation']['enabled'],
                escalationCheapModel: $config['audit']['escalation']['cheap_model'],
                structuredCollection: $config['audit']['structured_collection'] ?? true,
                reviewerStructuredCollection: $config['audit']['reviewer_structured_collection'] ?? true,
                stableSystemPrompt: $config['audit']['stable_system_prompt'] ?? true,
                baseline: $config['audit']['baseline'] ?? null,
                failOn: RiskLevel::from($config['audit']['fail_on'] ?? 'critical'),
                excludedTypes: $config['audit']['excluded_types'] ?? [],
                includedTypes: $config['audit']['included_types'] ?? [],
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
