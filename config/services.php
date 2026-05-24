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

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestratorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CharacterBasedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\StaticPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\SymfonyToolRegistryFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriterInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $defaultsConfigurator = $containerConfigurator->services()
        ->defaults()
            ->autowire()
            ->autoconfigure()
            ->private();

    $defaultsConfigurator
        ->instanceof(StageInterface::class)
        ->tag('symfony_security_auditor.pipeline_stage');

    $defaultsConfigurator->set(TokenUsageRecorder::class);

    $defaultsConfigurator->set(StaticPricingProvider::class)
        ->args([service('logger')]);
    $defaultsConfigurator->alias(PricingProviderInterface::class, StaticPricingProvider::class);

    $defaultsConfigurator->set(CostCalculator::class)
        ->args([service(PricingProviderInterface::class)]);

    // `AuditBudget` is built in SymfonySecurityAuditorBundle::loadExtension() so the
    // factory selection (unlimited/forTokens/forCost/forBoth) is explicit per config.

    $defaultsConfigurator->set(BudgetTracker::class)
        ->args([
            service(AuditBudget::class),
            service(CostCalculator::class),
        ]);

    $defaultsConfigurator->set(RetryPolicy::class)
        ->args([
            param('symfony_security_auditor.audit.retry.max_attempts'),
            param('symfony_security_auditor.audit.retry.initial_delay_ms'),
            param('symfony_security_auditor.audit.retry.backoff_multiplier'),
            param('symfony_security_auditor.audit.retry.jitter_ratio'),
        ]);

    $defaultsConfigurator->set(TransientFailureClassifier::class);

    $defaultsConfigurator->set(CharacterBasedTokenEstimator::class);
    $defaultsConfigurator->alias(TokenEstimatorInterface::class, CharacterBasedTokenEstimator::class);

    $defaultsConfigurator->set(UsleepSleeper::class);
    $defaultsConfigurator->alias(SleeperInterface::class, UsleepSleeper::class);

    $defaultsConfigurator->set(NullSecretScrubber::class);

    $defaultsConfigurator->set(RegexSecretScrubber::class)
        ->args([param('symfony_security_auditor.scan.secret_scrubbing.additional_patterns')]);
    // `SecretScrubberInterface` alias is set in SymfonySecurityAuditorBundle::loadExtension()
    // based on `scan.secret_scrubbing.enabled`.

    $defaultsConfigurator->set(ProjectFileScanner::class)
        ->args([
            service('logger'),
            param('symfony_security_auditor.scan.excluded_dirs'),
            param('symfony_security_auditor.scan.respect_gitignore'),
            param('symfony_security_auditor.scan.max_file_size_kb'),
            null,
            service(SecretScrubberInterface::class),
        ]);
    $defaultsConfigurator->alias(ProjectFileScannerInterface::class, ProjectFileScanner::class);

    $defaultsConfigurator->set(VulnerabilityFactory::class);
    $defaultsConfigurator->set(AttackerPromptBuilder::class);
    $defaultsConfigurator->alias(AttackerPromptBuilderInterface::class, AttackerPromptBuilder::class);

    $defaultsConfigurator->set(ReviewerPromptBuilder::class);
    $defaultsConfigurator->alias(ReviewerPromptBuilderInterface::class, ReviewerPromptBuilder::class);

    $defaultsConfigurator->set(ReportRenderer::class);

    $defaultsConfigurator->set(ReportWriter::class);
    $defaultsConfigurator->alias(ReportWriterInterface::class, ReportWriter::class);

    $defaultsConfigurator->set(AuditExitCodeResolver::class);
    $defaultsConfigurator->alias(AuditExitCodeResolverInterface::class, AuditExitCodeResolver::class);

    $defaultsConfigurator->set(AuditPresenter::class);
    $defaultsConfigurator->alias(AuditPresenterInterface::class, AuditPresenter::class);

    $defaultsConfigurator->set(IngestionStage::class)
        ->args([service(ProjectFileScannerInterface::class), service('logger')]);

    $defaultsConfigurator->set(MappingStage::class)
        ->args([service('logger')]);

    $defaultsConfigurator->set(AuditOrchestrator::class)
        ->args([
            service(AttackerAgentInterface::class),
            service(ReviewerAgentInterface::class),
            service('logger'),
            param('symfony_security_auditor.audit.max_iterations'),
            param('symfony_security_auditor.audit.min_confidence'),
        ]);
    $defaultsConfigurator->alias(AuditOrchestratorInterface::class, AuditOrchestrator::class);

    $defaultsConfigurator->set(AuditStage::class)
        ->args([service(AuditOrchestratorInterface::class), service('logger')]);

    $defaultsConfigurator->set(AuditPipeline::class)
        ->args([
            tagged_iterator('symfony_security_auditor.pipeline_stage'),
            service('logger'),
        ]);

    $defaultsConfigurator->alias(PipelineInterface::class, AuditPipeline::class);

    $defaultsConfigurator->set(Filesystem::class);

    $defaultsConfigurator->set(NullAttackerCache::class);

    $defaultsConfigurator->set(FilesystemAttackerCache::class)
        ->args([
            param('symfony_security_auditor.cache.dir'),
            service(Filesystem::class),
            service('logger'),
        ]);

    $defaultsConfigurator->set(InMemoryAdvisoryDatabase::class);

    $defaultsConfigurator->set(SymfonyProcessComposerAuditRunner::class);
    $defaultsConfigurator->alias(ComposerAuditRunnerInterface::class, SymfonyProcessComposerAuditRunner::class);

    $defaultsConfigurator->set(ComposerAuditAdvisoryDatabase::class)
        ->args([
            service(ComposerAuditRunnerInterface::class),
            param('kernel.project_dir'),
            service('logger'),
        ]);

    // `AdvisoryDatabaseInterface` alias is set in SymfonySecurityAuditorBundle::loadExtension()
    // based on `audit.advisory_source` (default: in_memory).

    $defaultsConfigurator->set(SymfonyToolRegistryFactory::class)
        ->args([service('logger'), service(AdvisoryDatabaseInterface::class)]);
    $defaultsConfigurator->alias(ToolRegistryFactoryInterface::class, SymfonyToolRegistryFactory::class);

    $defaultsConfigurator->set(AttackerAgent::class)
        ->args([
            service('security_auditor.attacker_client'),
            service(AttackerPromptBuilderInterface::class),
            service(VulnerabilityFactory::class),
            service(AttackerCacheInterface::class),
            service('logger'),
            service(ToolRegistryFactoryInterface::class),
            param('symfony_security_auditor.audit.tools_enabled'),
            param('symfony_security_auditor.audit.max_tool_iterations'),
        ]);

    $defaultsConfigurator->alias(AttackerAgentInterface::class, AttackerAgent::class);

    $defaultsConfigurator->set(ReviewerAgent::class)
        ->args([
            service('security_auditor.reviewer_client'),
            service(ReviewerPromptBuilderInterface::class),
            service('logger'),
            param('symfony_security_auditor.audit.reviewer_batch_size'),
        ]);

    $defaultsConfigurator->alias(ReviewerAgentInterface::class, ReviewerAgent::class);

    $defaultsConfigurator->set(EstimateAuditCostUseCase::class)
        ->args([
            service(ProjectFileScannerInterface::class),
            service(TokenEstimatorInterface::class),
            service(CostCalculator::class),
            service('logger'),
            param('symfony_security_auditor.attacker_model'),
            param('symfony_security_auditor.audit.max_iterations'),
        ]);

    $defaultsConfigurator->set(RunAuditUseCase::class)
        ->args([
            service(PipelineInterface::class),
            service('logger'),
            service(TokenUsageRecorder::class),
            service(CostCalculator::class),
            param('symfony_security_auditor.attacker_model'),
        ]);

    $defaultsConfigurator->set(AuditCommand::class)
        ->args([
            service(RunAuditUseCase::class),
            service(ReportWriterInterface::class),
            service(AuditExitCodeResolverInterface::class),
            service(AuditPresenterInterface::class),
            service(EstimateAuditCostUseCase::class),
        ])
        ->tag('console.command');
};
