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

use JsonException;
use Psr\Clock\ClockInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * @phpstan-import-type BundleConfigArray from BundleConfiguration
 */
final class SymfonySecurityAuditorBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        (new AuditConfigurationDefinition())
            ->defineChildren($definition->rootNode()->children());
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @throws JsonException
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        /** @var BundleConfigArray $config */
        $bundleConfiguration = BundleConfiguration::fromArray($config);

        $this->registerParameters($builder, $bundleConfiguration);

        $services = $container->services();
        $this->registerBudget($services, $bundleConfiguration);
        $this->registerRateLimiter($services, $bundleConfiguration);
        $this->registerLlmClients($services, $bundleConfiguration);
        $this->registerImplementationAliases($services, $bundleConfiguration);
        $this->registerEscalation($services, $bundleConfiguration);
    }

    /**
     * @throws JsonException
     */
    private function registerParameters(ContainerBuilder $containerBuilder, BundleConfiguration $bundleConfiguration): void
    {
        (new ContainerParameterRegistrar())->register($bundleConfiguration, $containerBuilder);
    }

    private function registerBudget(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $maxTokens = $bundleConfiguration->budget->maxTokens;
        $maxCostUsd = $bundleConfiguration->budget->maxCostUsd;
        [$auditBudgetFactory, $auditBudgetArgs] = match (true) {
            null === $maxTokens && null === $maxCostUsd => [[AuditBudget::class, 'unlimited'], []],
            null !== $maxTokens && null !== $maxCostUsd => [[AuditBudget::class, 'forBoth'], [$maxTokens, $maxCostUsd]],
            null !== $maxTokens => [[AuditBudget::class, 'forTokens'], [$maxTokens]],
            default => [[AuditBudget::class, 'forCost'], [$maxCostUsd]],
        };

        $servicesConfigurator->set(AuditBudget::class)
            ->private()
            ->factory($auditBudgetFactory)
            ->args($auditBudgetArgs);
    }

    private function registerRateLimiter(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(NullRateLimiter::class)->private();

        if (!$bundleConfiguration->rateLimit->isEnabled()) {
            $servicesConfigurator->alias(RateLimiterInterface::class, NullRateLimiter::class);

            return;
        }

        $servicesConfigurator->set(RateLimitConfiguration::class)
            ->private()
            ->args([
                $bundleConfiguration->rateLimit->requestsPerMinute,
                $bundleConfiguration->rateLimit->inputTokensPerMinute,
                $bundleConfiguration->rateLimit->outputTokensPerMinute,
            ]);
        $servicesConfigurator->set(TokenBucketRateLimiter::class)
            ->private()
            ->args([
                service(RateLimitConfiguration::class),
                service(ClockInterface::class),
                service(SleeperInterface::class),
            ]);
        $servicesConfigurator->alias(RateLimiterInterface::class, TokenBucketRateLimiter::class);
    }

    private function registerLlmClients(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->set(RetryAfterHeaderParser::class)->private();

        $servicesConfigurator->set('security_auditor.attacker_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientArguments(
                $bundleConfiguration,
                $bundleConfiguration->llm->attackerModel(),
                $bundleConfiguration->llm->attackerMaxOutputTokens(),
            ));

        $servicesConfigurator->set('security_auditor.reviewer_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientArguments(
                $bundleConfiguration,
                $bundleConfiguration->llm->reviewerModel(),
                $bundleConfiguration->llm->reviewerMaxOutputTokens(),
            ));

        $servicesConfigurator->alias(LLMClientInterface::class, 'security_auditor.attacker_client');
    }

    private function registerImplementationAliases(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $servicesConfigurator->alias(AttackerCacheInterface::class, $bundleConfiguration->cache->enabled
            ? FilesystemAttackerCache::class
            : NullAttackerCache::class);

        $servicesConfigurator->alias(ReviewerCacheInterface::class, $bundleConfiguration->cache->enabled
            ? FilesystemReviewerCache::class
            : NullReviewerCache::class);

        $servicesConfigurator->alias(SecretScrubberInterface::class, $bundleConfiguration->scan->secretScrubbingEnabled
            ? RegexSecretScrubber::class
            : NullSecretScrubber::class);

        $servicesConfigurator->alias(AdvisoryDatabaseInterface::class, ComposerAuditAdvisoryDatabase::class);

        $servicesConfigurator->alias(StaticPreScannerInterface::class, $bundleConfiguration->audit->staticPreScanEnabled
            ? RegexStaticPreScanner::class
            : NullStaticPreScanner::class);

        $servicesConfigurator->alias(CodeSlicerInterface::class, $bundleConfiguration->audit->codeSlicingEnabled
            ? RegexCodeSlicer::class
            : NullCodeSlicer::class);
    }

    private function registerEscalation(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        if (!$bundleConfiguration->audit->escalationEnabled) {
            return;
        }

        $cheapModel = $bundleConfiguration->audit->escalationCheapModel ?? $bundleConfiguration->llm->reviewerModel();

        $servicesConfigurator->set('security_auditor.cheap_attacker_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientArguments(
                $bundleConfiguration,
                $cheapModel,
                $bundleConfiguration->llm->attackerMaxOutputTokens(),
            ));

        $servicesConfigurator->set('security_auditor.cheap_attacker', AttackerAgent::class)
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
                service(RecordVulnerabilityToolFactoryInterface::class),
                $bundleConfiguration->audit->structuredCollection,
                service(ProgressReporterInterface::class),
            ]);

        $servicesConfigurator->set(EscalatingAttackerAgent::class)
            ->private()
            ->args([
                service('security_auditor.cheap_attacker'),
                service(AttackerAgent::class),
                service('logger'),
            ]);

        $servicesConfigurator->alias(AttackerAgentInterface::class, EscalatingAttackerAgent::class);
    }

    /**
     * @return list<mixed>
     */
    private function llmClientArguments(BundleConfiguration $bundleConfiguration, string $model, ?int $maxOutputTokens): array
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
