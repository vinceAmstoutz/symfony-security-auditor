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
use Override;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\CustomAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditExecutionConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullTriageMemoryRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackSnapshotInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\DeferredAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\IsolatedComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemTriageMemoryStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AttackerAgentDefinitionFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CheapAttackerClientNoticePass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredOutputCaps;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterRegistrar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingCliAgentBridgeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\TypedNodeEnvPlaceholderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OfflineOnlyPlatformGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PricingPlatformPass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PulledModelNoticePass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\TypedNodeEnvPlaceholderFinder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\UnselectedPlatformsPass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\GitTrackedIgnoredFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ProcessCliAgentAccountProbe;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionCliInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionClis;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ProviderTokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\UnpricedCostCapWarning;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\UsageBookingClientFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\CompositeReviewerFeedbackProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfiguredAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\HtmlReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\MarkdownReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SarifImportingPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\SubscriptionAccountGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuardInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * @phpstan-import-type BundleConfigArray from BundleConfiguration
 */
final class SymfonySecurityAuditorBundle extends AbstractBundle
{
    #[Override]
    public function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new PricingPlatformPass(PlatformInterface::class));
        $container->addCompilerPass(new UnselectedPlatformsPass(PlatformInterface::class));
        $container->addCompilerPass(new CheapAttackerClientNoticePass());
        $container->addCompilerPass(new PulledModelNoticePass());
    }

    #[Override]
    public function configure(DefinitionConfigurator $definition): void
    {
        (new AuditConfigurationDefinition())
            ->defineChildren($definition->rootNode()->children());
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     * @throws MissingCliAgentBridgeException
     * @throws NonLocalPlatformEndpointException
     * @throws TypedNodeEnvPlaceholderException
     */
    #[Override]
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $this->assertNoEnvPlaceholderOnTypedSetting($config, $builder);

        $this->registerForAutoconfiguration($builder);
        $container->import('../config/services.php');

        $cliAgent = CliAgentPlatforms::agentIn($config);
        if (null !== $cliAgent) {
            $config = CliAgentPlatforms::withToolFreeAudit($config);
            CliAgentPlatforms::register($builder, [$cliAgent => $config['cli_agent']]);
        }

        $platformServiceId = null === $cliAgent ? PlatformInterface::class : CliAgentPlatforms::serviceIdOf($cliAgent);
        $builder->setParameter(PulledModelNoticePass::PLATFORM_SERVICE_PARAMETER, $platformServiceId);

        /** @var BundleConfigArray $config */
        $bundleConfiguration = BundleConfiguration::fromArray($config);
        $this->assertCliAgentAllowed($bundleConfiguration, $cliAgent);

        $this->registerParameters($builder, $bundleConfiguration);

        $services = $container->services();
        $this->registerSubscriptionPricing($services, $cliAgent);
        $this->registerSubscriptionAccountGuard($services, $cliAgent, CliAgentPlatforms::cliBinaryIn($config));
        $this->registerBudget($services, $bundleConfiguration);
        $this->registerRateLimiter($services, $bundleConfiguration);
        $configuredOutputCaps = ConfiguredOutputCaps::in($config);
        $this->registerLlmClients($services, $bundleConfiguration, $platformServiceId, $configuredOutputCaps);
        $this->registerImplementationAliases($services, $bundleConfiguration);
        $this->registerTrackedIgnoredFiles($services, $bundleConfiguration);
        $this->registerCustomSkills($services, $bundleConfiguration);
        $this->registerEscalation($services, $bundleConfiguration, $platformServiceId, $configuredOutputCaps);
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    private function assertCliAgentAllowed(BundleConfiguration $bundleConfiguration, ?string $cliAgent): void
    {
        if (null !== $cliAgent && $bundleConfiguration->privacy->offlineOnly) {
            (new OfflineOnlyPlatformGuard())->assertIsNoCliAgent($cliAgent);
        }
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @throws TypedNodeEnvPlaceholderException
     */
    private function assertNoEnvPlaceholderOnTypedSetting(array $config, ContainerBuilder $containerBuilder): void
    {
        $paths = (new TypedNodeEnvPlaceholderFinder())->pathsIn($config, $containerBuilder->getParameterBag());

        if ([] !== $paths) {
            throw TypedNodeEnvPlaceholderException::forPaths($paths);
        }
    }

    /**
     * Every autoconfigured service implementing an extension point joins its
     * tagged iterator, the application's own services included.
     */
    private function registerForAutoconfiguration(ContainerBuilder $containerBuilder): void
    {
        $containerBuilder->registerForAutoconfiguration(StageInterface::class)
            ->addTag('symfony_security_auditor.pipeline_stage');
        $containerBuilder->registerForAutoconfiguration(ProviderTokenEstimatorInterface::class)
            ->addTag('symfony_security_auditor.token_estimator');
    }

    /**
     * Lists the files git tracks although a `.gitignore` pattern matches them
     * only when `scan.include_tracked_ignored` and `scan.respect_gitignore` are
     * both on; otherwise no git process runs.
     */
    private function registerTrackedIgnoredFiles(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        if (!$bundleConfiguration->scan->respectGitignore || !$bundleConfiguration->scan->includeTrackedIgnored) {
            return;
        }

        $servicesConfigurator->set(GitTrackedIgnoredFiles::class)
            ->private()
            ->args([service('logger')]);
    }

    /**
     * Tags each `audit.custom_skills` entry as a `ConfiguredAttackerSkill`,
     * which `AttackerSkillRegistry` collects beside the built-in skills.
     */
    private function registerCustomSkills(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        foreach ($bundleConfiguration->audit->customSkills as $index => $customSkill) {
            $servicesConfigurator->set(\sprintf('security_auditor.custom_skill.%d', $index), ConfiguredAttackerSkill::class)
                ->private()
                ->args([
                    inline_service(CustomAttackerSkill::class)->args([
                        $customSkill->name,
                        $customSkill->fileType,
                        $customSkill->instructions,
                        $customSkill->priority,
                    ]),
                ])
                ->tag('symfony_security_auditor.attacker_skill');
        }
    }

    private function registerSubscriptionAccountGuard(ServicesConfigurator $servicesConfigurator, ?string $cliAgent, ?string $cliBinary): void
    {
        $subscriptionCli = null === $cliAgent ? null : SubscriptionClis::bundled()->of($cliAgent);
        if (!$subscriptionCli instanceof SubscriptionCliInterface) {
            return;
        }

        $servicesConfigurator->set(SubscriptionAccountGuard::class)
            ->decorate(UnpricedModelBudgetGuardInterface::class)
            ->args([service('.inner'), inline_service($subscriptionCli::class), $cliBinary, inline_service(ProcessCliAgentAccountProbe::class)]);
    }

    private function registerSubscriptionPricing(ServicesConfigurator $servicesConfigurator, ?string $cliAgent): void
    {
        if (null === $cliAgent) {
            return;
        }

        $servicesConfigurator->set(NullPricingProvider::class);
        $servicesConfigurator->alias(PricingProviderInterface::class, NullPricingProvider::class);
        $servicesConfigurator->get(UnpricedModelBudgetGuard::class)->arg('$cliAgent', $cliAgent);
        $servicesConfigurator->get(AuditPresenter::class)->arg('$cliAgent', $cliAgent);
        foreach ([ConsoleReportRenderer::class, MarkdownReportRenderer::class, HtmlReportRenderer::class] as $renderer) {
            $servicesConfigurator->get($renderer)->arg('$subscription', SubscriptionClis::bundled()->of($cliAgent)?->subscription());
        }
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
                service(Clock::class),
                service(SleeperInterface::class),
            ]);
        $servicesConfigurator->alias(RateLimiterInterface::class, TokenBucketRateLimiter::class);
    }

    private function registerLlmClients(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration, string $platformServiceId, ConfiguredOutputCaps $configuredOutputCaps): void
    {
        $servicesConfigurator->set(RetryAfterHeaderParser::class)->private();

        $servicesConfigurator->set('security_auditor.attacker_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientArguments(
                $bundleConfiguration,
                $bundleConfiguration->llm->attackerModel(),
                $bundleConfiguration->llm->attackerMaxOutputTokens(),
                $platformServiceId,
                $configuredOutputCaps->attacker,
            ));

        $servicesConfigurator->set('security_auditor.reviewer_client', SymfonyAiLLMClient::class)
            ->private()
            ->args($this->llmClientArguments(
                $bundleConfiguration,
                $bundleConfiguration->llm->reviewerModel(),
                $bundleConfiguration->llm->reviewerMaxOutputTokens(),
                $platformServiceId,
                $configuredOutputCaps->reviewer,
            ));

        $servicesConfigurator->alias(LLMClientInterface::class, 'security_auditor.attacker_client');

        $this->bookUsageOfReplacedClients($servicesConfigurator);
    }

    /**
     * Books the usage of a client the application wires in place of either one
     * exactly once: this decorator wraps it before any of the application's.
     */
    private function bookUsageOfReplacedClients(ServicesConfigurator $servicesConfigurator): void
    {
        $servicesConfigurator->set(UnpricedCostCapWarning::class)
            ->private()
            ->args([
                service(AuditBudget::class),
                service(CostCalculator::class),
                service(PricingProviderInterface::class),
                service('logger'),
            ]);

        $this->bookUsageOf($servicesConfigurator, 'security_auditor.attacker_client');
        $this->bookUsageOf($servicesConfigurator, 'security_auditor.reviewer_client');
    }

    private function bookUsageOf(ServicesConfigurator $servicesConfigurator, string $clientId): void
    {
        $servicesConfigurator->set(\sprintf('%s.usage_booking', $clientId), LLMClientInterface::class)
            ->private()
            ->decorate($clientId, null, \PHP_INT_MAX)
            ->factory([UsageBookingClientFactory::class, 'around'])
            ->args([
                service('.inner'),
                service(TokenUsageRecorder::class),
                service(BudgetTracker::class),
                service(UnpricedCostCapWarning::class),
            ]);
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

        $servicesConfigurator->alias(AdvisoryDatabaseInterface::class, $bundleConfiguration->privacy->offlineOnly
            ? InMemoryAdvisoryDatabase::class
            : DeferredAdvisoryDatabase::class);

        $servicesConfigurator->alias(ComposerAuditRunnerInterface::class, $bundleConfiguration->cache->enabled
            ? LockfileHashedAdvisoryCache::class
            : IsolatedComposerAuditRunner::class);

        $this->registerStaticPreScanner($servicesConfigurator, $bundleConfiguration);
        $this->registerTriageMemory($servicesConfigurator, $bundleConfiguration);

        $servicesConfigurator->alias(CodeSlicerInterface::class, $bundleConfiguration->audit->codeSlicingEnabled
            ? RegexCodeSlicer::class
            : NullCodeSlicer::class);
    }

    /**
     * With `audit.triage_memory` on, the reviewer's rejections persist across
     * runs and merge with the baseline feedback through
     * {@see CompositeReviewerFeedbackProvider}; off, the default, only the
     * baseline feeds the reviewer.
     */
    private function registerTriageMemory(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        if (!$bundleConfiguration->audit->triageMemory) {
            $servicesConfigurator->alias(TriageMemoryRecorderInterface::class, NullTriageMemoryRecorder::class);
            $servicesConfigurator->alias(ReviewerFeedbackProviderInterface::class, ReviewerFeedbackHolder::class);

            return;
        }

        $servicesConfigurator->alias(TriageMemoryRecorderInterface::class, FilesystemTriageMemoryStore::class);
        $servicesConfigurator->alias(ReviewerFeedbackProviderInterface::class, CompositeReviewerFeedbackProvider::class);
        $servicesConfigurator->alias(ReviewerFeedbackSnapshotInterface::class, CompositeReviewerFeedbackProvider::class);
    }

    /**
     * With `scan.import_sarif` set, the SARIF importer decorates whichever
     * pre-scanner `audit.static_prescan` selected, so imports work even with
     * the regex pre-scan off.
     */
    private function registerStaticPreScanner(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        $staticPreScanner = $bundleConfiguration->audit->staticPreScanEnabled
            ? RegexStaticPreScanner::class
            : NullStaticPreScanner::class;

        if ([] === $bundleConfiguration->scan->importSarifPaths) {
            $servicesConfigurator->alias(StaticPreScannerInterface::class, $staticPreScanner);

            return;
        }

        $servicesConfigurator->set(SarifImportingPreScanner::class)
            ->private()
            ->args([
                service($staticPreScanner),
                $bundleConfiguration->scan->importSarifPaths,
                service(Filesystem::class),
                service(AuditedProjectPathHolder::class),
            ]);
        $servicesConfigurator->alias(StaticPreScannerInterface::class, SarifImportingPreScanner::class);
    }

    private function registerEscalation(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration, string $platformServiceId, ConfiguredOutputCaps $configuredOutputCaps): void
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
                $platformServiceId,
                $configuredOutputCaps->attacker,
            ));
        $this->bookUsageOf($servicesConfigurator, 'security_auditor.cheap_attacker_client');

        $this->registerCheapAttackerCache($servicesConfigurator, $bundleConfiguration);

        $servicesConfigurator->set('security_auditor.cheap_attacker', AttackerAgent::class)
            ->private()
            ->args((new AttackerAgentDefinitionFactory())->args(
                'security_auditor.cheap_attacker_client',
                'security_auditor.cheap_attacker_cache',
            ));

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
     * The cheap attacker never shares cache entries with the primary one,
     * which would otherwise be served a cheap model's empty result as its own
     * analysis.
     */
    private function registerCheapAttackerCache(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void
    {
        if (!$bundleConfiguration->cache->enabled) {
            $servicesConfigurator->alias('security_auditor.cheap_attacker_cache', NullAttackerCache::class);

            return;
        }

        $servicesConfigurator->set('security_auditor.cheap_attacker_cache', FilesystemAttackerCache::class)
            ->private()
            ->args([
                param('symfony_security_auditor.cache.dir'),
                service(Filesystem::class),
                service('logger'),
                param('symfony_security_auditor.cache.cheap_attacker_key_salt'),
            ]);
    }

    /**
     * Streams only the calls to the application's own platform: a coding
     * agent's CLI answers in one piece.
     */
    private function streamsCalls(string $platformServiceId): bool
    {
        return PlatformInterface::class === $platformServiceId;
    }

    /**
     * @return list<mixed>
     */
    private function llmClientArguments(BundleConfiguration $bundleConfiguration, string $model, ?int $maxOutputTokens, string $platformServiceId, bool $capsEveryModel): array
    {
        return [
            inline_service(PlatformBinding::class)->args([
                service($platformServiceId)->nullOnInvalid(),
                $model,
                service('logger'),
                $maxOutputTokens,
                param(UnselectedPlatformsPass::PARAMETER),
            ]),
            inline_service(PlatformRequestConfig::class)->args([
                SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
                $bundleConfiguration->llm->providerJsonMode,
                service(TokenEstimatorInterface::class),
                param(PricingPlatformPass::PARAMETER),
                $this->streamsCalls($platformServiceId),
                $capsEveryModel,
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
