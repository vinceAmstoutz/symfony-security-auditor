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

use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Builds the argument list every `SymfonyAiLLMClient` definition takes, so the
 * attacker, reviewer and escalation cheap-model clients cannot drift apart.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LlmClientDefinitionFactory
{
    /**
     * @return list<mixed>
     */
    public function args(BundleConfiguration $bundleConfiguration, string $model, ?int $maxOutputTokens): array
    {
        return [
            inline_service(PlatformBinding::class)->args([
                service(PlatformInterface::class)->nullOnInvalid(),
                $model,
                service('logger'),
                $maxOutputTokens,
            ]),
            inline_service(PlatformRequestConfig::class)->args([
                SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                $bundleConfiguration->llm->providerJsonMode,
                service(TokenEstimatorInterface::class),
            ]),
            inline_service(PlatformResilienceConfig::class)->args([
                service(RetryPolicy::class),
                service(TransientFailureClassifier::class),
                service(RetryAfterHeaderParser::class),
                service(SleeperInterface::class),
                service(RateLimiterInterface::class),
            ]),
            inline_service(PlatformAccountingConfig::class)->args([
                service(TokenUsageRecorder::class),
                service(BudgetTracker::class),
            ]),
        ];
    }
}
