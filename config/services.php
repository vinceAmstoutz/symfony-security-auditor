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
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestratorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\PoCSynthesizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\PoCSynthesizerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\PoCSynthesisStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\VoterCapabilityParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Diff\ProcessGitChangedFilesResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CharacterBasedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\StaticPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\LoggerProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\SymfonyToolRegistryFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriterInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
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
            param('symfony_security_auditor.scan.included_paths'),
            param('symfony_security_auditor.scan.respect_gitignore'),
            param('symfony_security_auditor.scan.max_file_size_kb'),
            null,
            service(SecretScrubberInterface::class),
        ]);
    $defaultsConfigurator->alias(ProjectFileScannerInterface::class, ProjectFileScanner::class);

    $defaultsConfigurator->set(VulnerabilityFactory::class)
        ->args([
            service('logger')->ignoreOnInvalid(),
            inline_service(ValidatorInterface::class)->factory([Validation::class, 'createValidator']),
        ]);
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

    $defaultsConfigurator->set(ProcessGitChangedFilesResolver::class);
    $defaultsConfigurator->alias(GitChangedFilesResolverInterface::class, ProcessGitChangedFilesResolver::class);

    $defaultsConfigurator->set(IngestionStage::class)
        ->args([
            service(ProjectFileScannerInterface::class),
            service('logger'),
            service(GitChangedFilesResolverInterface::class),
        ]);

    $defaultsConfigurator->set(PhpParserControllerAccessControlParser::class);
    $defaultsConfigurator->alias(ControllerAccessControlParserInterface::class, PhpParserControllerAccessControlParser::class);

    $defaultsConfigurator->set(PhpParserVoterCapabilityParser::class);
    $defaultsConfigurator->alias(VoterCapabilityParserInterface::class, PhpParserVoterCapabilityParser::class);

    $defaultsConfigurator->set(PhpParserFormBindingParser::class);
    $defaultsConfigurator->alias(FormBindingParserInterface::class, PhpParserFormBindingParser::class);

    $defaultsConfigurator->set(MappingStage::class)
        ->args([
            service('logger'),
            service(ControllerAccessControlParserInterface::class),
            service(VoterCapabilityParserInterface::class),
            service(FormBindingParserInterface::class),
        ]);

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

    $defaultsConfigurator->set(PoCSynthesizer::class)
        ->args([
            service('security_auditor.reviewer_client'),
            service('logger'),
            inline_service(VulnerabilitySeverity::class)
                ->factory([VulnerabilitySeverity::class, 'from'])
                ->args([param('symfony_security_auditor.audit.poc_synthesis.severity_floor')]),
        ]);
    $defaultsConfigurator->alias(PoCSynthesizerInterface::class, PoCSynthesizer::class);

    $defaultsConfigurator->set(PoCSynthesisStage::class)
        ->args([
            service(PoCSynthesizerInterface::class),
            service('logger'),
            param('symfony_security_auditor.audit.poc_synthesis.enabled'),
        ]);

    $defaultsConfigurator->set(NullProgressReporter::class);
    $defaultsConfigurator->set(LoggerProgressReporter::class)
        ->args([service('logger')]);
    $defaultsConfigurator->set(ProgressReporterHolder::class);
    $defaultsConfigurator->alias(ProgressReporterInterface::class, ProgressReporterHolder::class);

    $defaultsConfigurator->set(AuditPipeline::class)
        ->args([
            tagged_iterator('symfony_security_auditor.pipeline_stage'),
            service('logger'),
            service(ProgressReporterInterface::class),
        ]);

    $defaultsConfigurator->alias(PipelineInterface::class, AuditPipeline::class);

    $defaultsConfigurator->set(Filesystem::class);

    $defaultsConfigurator->set(NullAttackerCache::class);

    $defaultsConfigurator->set(FilesystemAttackerCache::class)
        ->args([
            param('symfony_security_auditor.cache.dir'),
            service(Filesystem::class),
            service('logger'),
            param('symfony_security_auditor.cache.key_salt'),
        ]);

    $defaultsConfigurator->set(InMemoryAdvisoryDatabase::class);

    $defaultsConfigurator->set(SymfonyProcessComposerAuditRunner::class);

    $defaultsConfigurator->set(LockfileHashedAdvisoryCache::class)
        ->args([
            service(SymfonyProcessComposerAuditRunner::class),
            param('symfony_security_auditor.cache.advisory_dir'),
            service(Filesystem::class),
            service('logger'),
        ]);
    $defaultsConfigurator->alias(ComposerAuditRunnerInterface::class, LockfileHashedAdvisoryCache::class);

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

    $defaultsConfigurator->set(NullStaticPreScanner::class);
    $defaultsConfigurator->set(RegexStaticPreScanner::class)
        ->args([param('symfony_security_auditor.scan.custom_risk_patterns')]);

    $defaultsConfigurator->set(NullCodeSlicer::class);
    $defaultsConfigurator->set(RegexCodeSlicer::class)
        ->args([param('symfony_security_auditor.audit.code_slicing.min_lines_before_slicing')]);

    $defaultsConfigurator->set(FileChunker::class)
        ->args([
            inline_service(ChunkingStrategy::class)
                ->factory([ChunkingStrategy::class, 'from'])
                ->args([param('symfony_security_auditor.audit.chunking.strategy')]),
        ]);

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
            service(StaticPreScannerInterface::class),
            param('symfony_security_auditor.audit.static_prescan.lean_mode'),
            service(FileChunker::class),
            service(CodeSlicerInterface::class),
        ]);

    $defaultsConfigurator->alias(AttackerAgentInterface::class, AttackerAgent::class);

    $defaultsConfigurator->set(ReviewerAgent::class)
        ->args([
            service('security_auditor.reviewer_client'),
            service(ReviewerPromptBuilderInterface::class),
            service('logger'),
            param('symfony_security_auditor.audit.reviewer_batch_size'),
            service(ToolRegistryFactoryInterface::class),
            param('symfony_security_auditor.audit.reviewer_tools_enabled'),
            param('symfony_security_auditor.audit.reviewer_max_tool_iterations'),
            param('symfony_security_auditor.audit.reviewer_max_concurrent'),
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
            EstimateAuditCostUseCase::DEFAULT_OUTPUT_RATIO,
            param('symfony_security_auditor.reviewer_model'),
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
            service(ProgressReporterHolder::class),
            param('symfony_security_auditor.scan.secret_scrubbing.enabled'),
        ])
        ->tag('console.command');
};
