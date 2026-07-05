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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use JsonException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use UnitEnum;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ConfigurationNotices;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\LLMConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;

/**
 * @internal
 */
final readonly class ContainerParameterRegistrar
{
    private const string PREFIX = 'symfony_security_auditor.';

    /**
     * @throws JsonException
     */
    public function register(BundleConfiguration $bundleConfiguration, ContainerBuilder $containerBuilder): void
    {
        foreach ($this->parameters($bundleConfiguration) as $name => $value) {
            $containerBuilder->setParameter(self::PREFIX.$name, $value);
        }
    }

    /**
     * @return array<string, array<array-key, mixed>|bool|float|int|string|UnitEnum|null>
     *
     * @throws JsonException
     */
    private function parameters(BundleConfiguration $bundleConfiguration): array
    {
        $llm = $bundleConfiguration->llm;
        $scan = $bundleConfiguration->scan;
        $audit = $bundleConfiguration->audit;
        $cache = $bundleConfiguration->cache;
        $budget = $bundleConfiguration->budget;
        $retry = $bundleConfiguration->retry;

        return [
            'attacker_model' => $llm->attackerModel(),
            'reviewer_model' => $llm->reviewerModel(),
            'attacker_max_output_tokens' => $llm->attackerMaxOutputTokens(),
            'reviewer_max_output_tokens' => $llm->reviewerMaxOutputTokens(),
            'scan.included_paths' => $scan->includedPaths,
            'scan.respect_gitignore' => $scan->respectGitignore,
            'scan.max_file_size_kb' => $scan->maxFileSizeKb,
            'scan.secret_scrubbing.enabled' => $scan->secretScrubbingEnabled,
            'scan.secret_scrubbing.additional_patterns' => $scan->additionalScrubberPatterns,
            'scan.custom_risk_patterns' => $scan->customRiskPatterns,
            'audit.max_iterations' => $audit->maxIterations,
            'audit.min_confidence' => $audit->minConfidence,
            'audit.reviewer_batch_size' => $audit->reviewerBatchSize,
            'audit.tools_enabled' => $audit->toolsEnabled,
            'audit.structured_collection' => $audit->structuredCollection,
            'audit.reviewer_structured_collection' => $audit->reviewerStructuredCollection,
            'audit.stable_system_prompt' => $audit->stableSystemPrompt,
            'audit.max_tool_iterations' => $audit->maxToolIterations,
            'audit.reviewer_tools_enabled' => $audit->reviewerToolsEnabled,
            'audit.reviewer_max_tool_iterations' => $audit->reviewerMaxToolIterations,
            'audit.baseline' => $audit->baseline,
            'audit.fail_on' => $audit->failOn->value,
            'audit.excluded_types' => $audit->excludedTypes,
            'audit.included_types' => $audit->includedTypes,
            'audit.reviewer_max_concurrent' => $audit->reviewerMaxConcurrent,
            'audit.attacker_max_concurrent' => $audit->attackerMaxConcurrent,
            'audit.static_prescan.enabled' => $audit->staticPreScanEnabled,
            'audit.static_prescan.lean_mode' => $audit->staticPreScanLeanMode,
            'audit.chunking.strategy' => $audit->chunkingStrategy,
            'audit.poc_synthesis.enabled' => $audit->poCSynthesisEnabled,
            'audit.poc_synthesis.severity_floor' => $audit->poCSynthesisSeverityFloor,
            'audit.code_slicing.enabled' => $audit->codeSlicingEnabled,
            'audit.code_slicing.min_lines_before_slicing' => $audit->codeSlicingMinLines,
            'audit.budget.max_tokens' => $budget->maxTokens,
            'audit.budget.max_cost_usd' => $budget->maxCostUsd,
            'audit.retry.max_attempts' => $retry->maxAttempts,
            'audit.retry.initial_delay_ms' => $retry->initialDelayMs,
            'audit.retry.backoff_multiplier' => $retry->backoffMultiplier,
            'audit.retry.jitter_ratio' => $retry->jitterRatio,
            'config_notices' => ConfigurationNotices::of($audit, $llm),
            'cache.enabled' => $cache->enabled,
            'cache.dir' => $cache->dir,
            'cache.advisory_dir' => \sprintf('%s/advisory', $cache->dir),
            'cache.reviewer_dir' => \sprintf('%s/reviewer', $cache->dir),
            'cache.reviewer_key_salt' => $this->reviewerKeySalt($llm),
            'cache.prompt_caching' => $cache->promptCaching,
            'cache.key_salt' => $this->attackerKeySalt($bundleConfiguration),
        ];
    }

    private function reviewerKeySalt(LLMConfiguration $llmConfiguration): string
    {
        return \sprintf(
            '%s|reviewer-v%d|prompt-v%d',
            $llmConfiguration->reviewerModel(),
            FilesystemReviewerCache::CACHE_VERSION,
            ReviewerPromptBuilder::PROMPT_VERSION,
        );
    }

    /**
     * @throws JsonException
     */
    private function attackerKeySalt(BundleConfiguration $bundleConfiguration): string
    {
        return \sprintf(
            '%s|prompt-v%d|prescan-v%d|patterns-%s|collect-%s|skills-%s|slice-%s',
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
            $bundleConfiguration->audit->structuredCollection ? 'tool' : 'json',
            $bundleConfiguration->audit->stableSystemPrompt ? 'full' : 'lean',
            $this->codeSlicingSalt($bundleConfiguration),
        );
    }

    private function codeSlicingSalt(BundleConfiguration $bundleConfiguration): string
    {
        if (!$bundleConfiguration->audit->codeSlicingEnabled) {
            return 'off';
        }

        return \sprintf('on-%d', $bundleConfiguration->audit->codeSlicingMinLines);
    }
}
