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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ConfigurationNotices;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;

/**
 * @internal
 */
final readonly class ContainerParameterRegistrar
{
    /**
     * @throws JsonException
     */
    public function register(BundleConfiguration $bundleConfiguration, ContainerBuilder $containerBuilder): void
    {
        $containerBuilder->setParameter('symfony_security_auditor.attacker_model', $bundleConfiguration->llm->attackerModel());
        $containerBuilder->setParameter('symfony_security_auditor.reviewer_model', $bundleConfiguration->llm->reviewerModel());
        $containerBuilder->setParameter('symfony_security_auditor.attacker_max_output_tokens', $bundleConfiguration->llm->attackerMaxOutputTokens());
        $containerBuilder->setParameter('symfony_security_auditor.reviewer_max_output_tokens', $bundleConfiguration->llm->reviewerMaxOutputTokens());
        $containerBuilder->setParameter('symfony_security_auditor.scan.included_paths', $bundleConfiguration->scan->includedPaths);
        $containerBuilder->setParameter('symfony_security_auditor.scan.respect_gitignore', $bundleConfiguration->scan->respectGitignore);
        $containerBuilder->setParameter('symfony_security_auditor.scan.max_file_size_kb', $bundleConfiguration->scan->maxFileSizeKb);
        $containerBuilder->setParameter('symfony_security_auditor.scan.secret_scrubbing.enabled', $bundleConfiguration->scan->secretScrubbingEnabled);
        $containerBuilder->setParameter('symfony_security_auditor.scan.secret_scrubbing.additional_patterns', $bundleConfiguration->scan->additionalScrubberPatterns);
        $containerBuilder->setParameter('symfony_security_auditor.scan.custom_risk_patterns', $bundleConfiguration->scan->customRiskPatterns);
        $containerBuilder->setParameter('symfony_security_auditor.audit.max_iterations', $bundleConfiguration->audit->maxIterations);
        $containerBuilder->setParameter('symfony_security_auditor.audit.min_confidence', $bundleConfiguration->audit->minConfidence);
        $containerBuilder->setParameter('symfony_security_auditor.audit.reviewer_batch_size', $bundleConfiguration->audit->reviewerBatchSize);
        $containerBuilder->setParameter('symfony_security_auditor.audit.tools_enabled', $bundleConfiguration->audit->toolsEnabled);
        $containerBuilder->setParameter('symfony_security_auditor.audit.structured_collection', $bundleConfiguration->audit->structuredCollection);
        $containerBuilder->setParameter('symfony_security_auditor.audit.reviewer_structured_collection', $bundleConfiguration->audit->reviewerStructuredCollection);
        $containerBuilder->setParameter('symfony_security_auditor.audit.stable_system_prompt', $bundleConfiguration->audit->stableSystemPrompt);
        $containerBuilder->setParameter('symfony_security_auditor.audit.max_tool_iterations', $bundleConfiguration->audit->maxToolIterations);
        $containerBuilder->setParameter('symfony_security_auditor.audit.reviewer_tools_enabled', $bundleConfiguration->audit->reviewerToolsEnabled);
        $containerBuilder->setParameter('symfony_security_auditor.audit.reviewer_max_tool_iterations', $bundleConfiguration->audit->reviewerMaxToolIterations);
        $containerBuilder->setParameter('symfony_security_auditor.audit.baseline', $bundleConfiguration->audit->baseline);
        $containerBuilder->setParameter('symfony_security_auditor.audit.fail_on', $bundleConfiguration->audit->failOn->value);
        $containerBuilder->setParameter('symfony_security_auditor.audit.excluded_types', $bundleConfiguration->audit->excludedTypes);
        $containerBuilder->setParameter('symfony_security_auditor.audit.included_types', $bundleConfiguration->audit->includedTypes);
        $containerBuilder->setParameter('symfony_security_auditor.audit.reviewer_max_concurrent', $bundleConfiguration->audit->reviewerMaxConcurrent);
        $containerBuilder->setParameter('symfony_security_auditor.audit.attacker_max_concurrent', $bundleConfiguration->audit->attackerMaxConcurrent);
        $containerBuilder->setParameter('symfony_security_auditor.audit.static_prescan.enabled', $bundleConfiguration->audit->staticPreScanEnabled);
        $containerBuilder->setParameter('symfony_security_auditor.audit.static_prescan.lean_mode', $bundleConfiguration->audit->staticPreScanLeanMode);
        $containerBuilder->setParameter('symfony_security_auditor.audit.chunking.strategy', $bundleConfiguration->audit->chunkingStrategy);
        $containerBuilder->setParameter('symfony_security_auditor.audit.poc_synthesis.enabled', $bundleConfiguration->audit->poCSynthesisEnabled);
        $containerBuilder->setParameter('symfony_security_auditor.audit.poc_synthesis.severity_floor', $bundleConfiguration->audit->poCSynthesisSeverityFloor);
        $containerBuilder->setParameter('symfony_security_auditor.audit.code_slicing.enabled', $bundleConfiguration->audit->codeSlicingEnabled);
        $containerBuilder->setParameter('symfony_security_auditor.audit.code_slicing.min_lines_before_slicing', $bundleConfiguration->audit->codeSlicingMinLines);
        $containerBuilder->setParameter('symfony_security_auditor.audit.budget.max_tokens', $bundleConfiguration->budget->maxTokens);
        $containerBuilder->setParameter('symfony_security_auditor.audit.budget.max_cost_usd', $bundleConfiguration->budget->maxCostUsd);
        $containerBuilder->setParameter('symfony_security_auditor.audit.retry.max_attempts', $bundleConfiguration->retry->maxAttempts);
        $containerBuilder->setParameter('symfony_security_auditor.audit.retry.initial_delay_ms', $bundleConfiguration->retry->initialDelayMs);
        $containerBuilder->setParameter('symfony_security_auditor.audit.retry.backoff_multiplier', $bundleConfiguration->retry->backoffMultiplier);
        $containerBuilder->setParameter('symfony_security_auditor.audit.retry.jitter_ratio', $bundleConfiguration->retry->jitterRatio);

        $containerBuilder->setParameter('symfony_security_auditor.config_notices', ConfigurationNotices::of($bundleConfiguration->audit, $bundleConfiguration->llm));
        $containerBuilder->setParameter('symfony_security_auditor.cache.enabled', $bundleConfiguration->cache->enabled);
        $containerBuilder->setParameter('symfony_security_auditor.cache.dir', $bundleConfiguration->cache->dir);
        $containerBuilder->setParameter('symfony_security_auditor.cache.advisory_dir', $bundleConfiguration->cache->dir.'/advisory');
        $containerBuilder->setParameter('symfony_security_auditor.cache.reviewer_dir', $bundleConfiguration->cache->dir.'/reviewer');
        $containerBuilder->setParameter(
            'symfony_security_auditor.cache.reviewer_key_salt',
            \sprintf('%s|reviewer-v%d|prompt-v%d', $bundleConfiguration->llm->reviewerModel(), FilesystemReviewerCache::CACHE_VERSION, ReviewerPromptBuilder::PROMPT_VERSION),
        );
        $containerBuilder->setParameter('symfony_security_auditor.cache.prompt_caching', $bundleConfiguration->cache->promptCaching);
        $containerBuilder->setParameter(
            'symfony_security_auditor.cache.key_salt',
            \sprintf(
                '%s|prompt-v%d|prescan-v%d|patterns-%s|collect-%s|skills-%s',
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
            ),
        );
    }
}
