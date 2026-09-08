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

use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AuditOrchestratorInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\FixSynthesizer;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\FixSynthesizerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\PoCSynthesizer;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\PoCSynthesizerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\Stage\DependencyExpansionStage;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\Stage\FixSynthesisStage;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\Stage\PoCSynthesisStage;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AccessControlConfigParserInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AttackerSkillPromptRendererInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AuthorizationRuleParserInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\EntrypointAccessControlParserInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullTriageMemoryRecorder;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ProjectFileTypeClassifierInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerFeedbackSnapshotInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\DeferredAdvisoryDatabase;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\FilesystemTriageMemoryStore;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Diff\ProcessGitChangedFilesResolver;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Feedback\CompositeReviewerFeedbackProvider;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Feedback\ReviewerFeedbackHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\BackoffSchedule;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\AnthropicTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\CharacterRatioCounter;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\DeepSeekTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\GeminiTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\LlamaTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\MiniMaxTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\MistralTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\OpenAiTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ProviderTokenEstimatorInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Progress\LoggerProgressReporter;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\ExecutiveSummaryReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\GithubAnnotationsReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\GithubCommentReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\HtmlReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\MarkdownReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Skill\AttackerSkillInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SecurityAuditor\Command\AuditExitCodeResolverInterface;
use VinceAmstoutz\SecurityAuditor\Command\AuditFailureExitCodeListener;
use VinceAmstoutz\SecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SecurityAuditor\Command\AuditPresenterInterface;
use VinceAmstoutz\SecurityAuditor\Command\Baseline;
use VinceAmstoutz\SecurityAuditor\Command\BaselineCommand;
use VinceAmstoutz\SecurityAuditor\Command\BaselineInterface;
use VinceAmstoutz\SecurityAuditor\Command\BaselineMerger;
use VinceAmstoutz\SecurityAuditor\Command\BaselineMergerInterface;
use VinceAmstoutz\SecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SecurityAuditor\Command\BaselineProcessorInterface;
use VinceAmstoutz\SecurityAuditor\Command\ConsoleBanner;
use VinceAmstoutz\SecurityAuditor\Command\ConsoleBannerInterface;
use VinceAmstoutz\SecurityAuditor\Command\DiffCommand;
use VinceAmstoutz\SecurityAuditor\Command\DiffPresenter;
use VinceAmstoutz\SecurityAuditor\Command\DiffPresenterInterface;
use VinceAmstoutz\SecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SecurityAuditor\Command\FindingTypeFilterInterface;
use VinceAmstoutz\SecurityAuditor\Command\Mcp\AuditTool;
use VinceAmstoutz\SecurityAuditor\Command\Mcp\McpServeCommand;
use VinceAmstoutz\SecurityAuditor\Command\Mcp\McpServerFactory;
use VinceAmstoutz\SecurityAuditor\Command\Mcp\McpServerFactoryInterface;
use VinceAmstoutz\SecurityAuditor\Command\Mcp\McpTransportFactoryInterface;
use VinceAmstoutz\SecurityAuditor\Command\Mcp\StdioMcpTransportFactory;
use VinceAmstoutz\SecurityAuditor\Command\ReportDiffer;
use VinceAmstoutz\SecurityAuditor\Command\ReportDifferInterface;
use VinceAmstoutz\SecurityAuditor\Command\ReportFindingsLoader;
use VinceAmstoutz\SecurityAuditor\Command\ReportFindingsLoaderInterface;
use VinceAmstoutz\SecurityAuditor\Command\ReportTrendAnalyzer;
use VinceAmstoutz\SecurityAuditor\Command\ReportTrendAnalyzerInterface;
use VinceAmstoutz\SecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SecurityAuditor\Command\ReportWriterInterface;
use VinceAmstoutz\SecurityAuditor\Command\TrendCommand;
use VinceAmstoutz\SecurityAuditor\Command\TrendHtmlRenderer;
use VinceAmstoutz\SecurityAuditor\Command\TrendHtmlRendererInterface;
use VinceAmstoutz\SecurityAuditor\Command\TrendPresenter;
use VinceAmstoutz\SecurityAuditor\Command\TrendPresenterInterface;
use VinceAmstoutz\SecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SecurityAuditor\Command\UnpricedModelBudgetGuardInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AttackerAgentDefinitionFactory;

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

    $defaultsConfigurator
        ->instanceof(ProviderTokenEstimatorInterface::class)
        ->tag('symfony_security_auditor.token_estimator');

    $defaultsConfigurator
        ->instanceof(ReportRendererInterface::class)
        ->tag('symfony_security_auditor.report_renderer');

    $defaultsConfigurator
        ->instanceof(AttackerSkillInterface::class)
        ->tag('symfony_security_auditor.attacker_skill');

    $defaultsConfigurator->set(TokenUsageRecorder::class);

    $defaultsConfigurator->set(ModelsDevPricingProvider::class)
        ->args([service('logger'), '%kernel.cache_dir%/models-dev.json']);
    $defaultsConfigurator->alias(PricingProviderInterface::class, ModelsDevPricingProvider::class);

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
            inline_service(BackoffSchedule::class)->args([
                param('symfony_security_auditor.audit.retry.max_attempts'),
                param('symfony_security_auditor.audit.retry.initial_delay_ms'),
                param('symfony_security_auditor.audit.retry.backoff_multiplier'),
                param('symfony_security_auditor.audit.retry.jitter_ratio'),
            ]),
        ]);

    $defaultsConfigurator->set(TransientFailureClassifier::class);

    $defaultsConfigurator->set(CharacterRatioCounter::class);
    $defaultsConfigurator->set(AnthropicTokenEstimator::class);
    $defaultsConfigurator->set(OpenAiTokenEstimator::class);
    $defaultsConfigurator->set(GeminiTokenEstimator::class);
    $defaultsConfigurator->set(MistralTokenEstimator::class);
    $defaultsConfigurator->set(LlamaTokenEstimator::class);
    $defaultsConfigurator->set(DeepSeekTokenEstimator::class);
    $defaultsConfigurator->set(MiniMaxTokenEstimator::class);
    $defaultsConfigurator->set(ResolvingTokenEstimator::class)
        ->args([tagged_iterator('symfony_security_auditor.token_estimator')]);
    $defaultsConfigurator->alias(TokenEstimatorInterface::class, ResolvingTokenEstimator::class);

    $defaultsConfigurator->set(UsleepSleeper::class);
    $defaultsConfigurator->alias(SleeperInterface::class, UsleepSleeper::class);

    $defaultsConfigurator->set(NullSecretScrubber::class);

    // `SecretScrubberInterface` alias is set in SymfonySecurityAuditorBundle::loadExtension()
    // based on `scan.secret_scrubbing.enabled`.
    $defaultsConfigurator->set(RegexSecretScrubber::class)
        ->args([
            param('symfony_security_auditor.scan.secret_scrubbing.additional_patterns'),
            service('logger'),
        ]);

    $defaultsConfigurator->set(ProjectFileScanner::class)
        ->args([
            service(ProjectFileTypeClassifierInterface::class),
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
    $defaultsConfigurator->set(NullTriageMemoryRecorder::class);

    $defaultsConfigurator->set(FilesystemTriageMemoryStore::class)
        ->args([
            param('symfony_security_auditor.cache.triage_memory_dir'),
            service(Filesystem::class),
            service('logger'),
            service(AuditedProjectPathHolder::class),
        ]);

    $defaultsConfigurator->set(CompositeReviewerFeedbackProvider::class)
        ->args([
            service(ReviewerFeedbackHolder::class),
            service(FilesystemTriageMemoryStore::class),
        ]);

    $defaultsConfigurator->set(ConsoleReportRenderer::class);
    $defaultsConfigurator->set(JsonReportRenderer::class);
    $defaultsConfigurator->set(SarifReportRenderer::class);
    $defaultsConfigurator->set(HtmlReportRenderer::class);
    $defaultsConfigurator->set(MarkdownReportRenderer::class);
    $defaultsConfigurator->set(JunitReportRenderer::class);
    $defaultsConfigurator->set(GithubAnnotationsReportRenderer::class);
    $defaultsConfigurator->set(GithubCommentReportRenderer::class);
    $defaultsConfigurator->set(ExecutiveSummaryReportRenderer::class);

    $defaultsConfigurator->set(ReportWriter::class)
        ->args([tagged_iterator('symfony_security_auditor.report_renderer')]);
    $defaultsConfigurator->alias(ReportWriterInterface::class, ReportWriter::class);

    $defaultsConfigurator->set(AuditExitCodeResolver::class);
    $defaultsConfigurator->alias(AuditExitCodeResolverInterface::class, AuditExitCodeResolver::class);

    $defaultsConfigurator->set(ConsoleBanner::class);
    $defaultsConfigurator->alias(ConsoleBannerInterface::class, ConsoleBanner::class);

    $defaultsConfigurator->set(AuditPresenter::class);
    $defaultsConfigurator->alias(AuditPresenterInterface::class, AuditPresenter::class);

    $defaultsConfigurator->set(Baseline::class);
    $defaultsConfigurator->alias(BaselineInterface::class, Baseline::class);

    $defaultsConfigurator->set(BaselineMerger::class)
        ->args([
            service(ReportFindingsLoaderInterface::class),
            service(BaselineInterface::class),
        ]);
    $defaultsConfigurator->alias(BaselineMergerInterface::class, BaselineMerger::class);

    $defaultsConfigurator->set(BaselineProcessor::class)
        ->args([
            service(BaselineInterface::class),
            param('symfony_security_auditor.audit.baseline'),
        ]);
    $defaultsConfigurator->alias(BaselineProcessorInterface::class, BaselineProcessor::class);

    $defaultsConfigurator->set(FindingTypeFilter::class)
        ->args([
            param('symfony_security_auditor.audit.included_types'),
            param('symfony_security_auditor.audit.excluded_types'),
        ]);
    $defaultsConfigurator->alias(FindingTypeFilterInterface::class, FindingTypeFilter::class);

    $defaultsConfigurator->set(ReportFindingsLoader::class);
    $defaultsConfigurator->alias(ReportFindingsLoaderInterface::class, ReportFindingsLoader::class);

    $defaultsConfigurator->set(ReportDiffer::class)
        ->args([
            service(ReportFindingsLoaderInterface::class),
        ]);
    $defaultsConfigurator->alias(ReportDifferInterface::class, ReportDiffer::class);

    $defaultsConfigurator->set(DiffPresenter::class);
    $defaultsConfigurator->alias(DiffPresenterInterface::class, DiffPresenter::class);

    $defaultsConfigurator->set(ReportTrendAnalyzer::class)
        ->args([
            service(ReportDifferInterface::class),
        ]);
    $defaultsConfigurator->alias(ReportTrendAnalyzerInterface::class, ReportTrendAnalyzer::class);

    $defaultsConfigurator->set(TrendHtmlRenderer::class);
    $defaultsConfigurator->alias(TrendHtmlRendererInterface::class, TrendHtmlRenderer::class);

    $defaultsConfigurator->set(TrendPresenter::class)
        ->args([
            service(TrendHtmlRendererInterface::class),
        ]);
    $defaultsConfigurator->alias(TrendPresenterInterface::class, TrendPresenter::class);

    $defaultsConfigurator->set(ProcessGitChangedFilesResolver::class);
    $defaultsConfigurator->alias(GitChangedFilesResolverInterface::class, ProcessGitChangedFilesResolver::class);

    $defaultsConfigurator->set(IngestionStage::class)
        ->args([
            service(ProjectFileScannerInterface::class),
            service('logger'),
            service(GitChangedFilesResolverInterface::class),
        ]);

    $defaultsConfigurator->set(MappingStage::class)
        ->args([
            service('logger'),
            service(EntrypointAccessControlParserInterface::class),
            service(AuthorizationRuleParserInterface::class),
            service(FormBindingParserInterface::class),
            service(AccessControlConfigParserInterface::class),
        ]);

    $defaultsConfigurator->set(DependencyExpansionStage::class)
        ->args([
            service('logger'),
            param('symfony_security_auditor.audit.since_closure'),
        ]);

    $defaultsConfigurator->set(AuditOrchestrator::class)
        ->args([
            service(AttackerAgentInterface::class),
            service(ReviewerAgentInterface::class),
            service('logger'),
            inline_service(AuditLoopSettings::class)->args([
                param('symfony_security_auditor.audit.max_iterations'),
                param('symfony_security_auditor.audit.min_confidence'),
            ]),
            service(ProgressReporterInterface::class),
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

    $defaultsConfigurator->set(FixSynthesizer::class)
        ->args([
            service('security_auditor.reviewer_client'),
            service('logger'),
            inline_service(VulnerabilitySeverity::class)
                ->factory([VulnerabilitySeverity::class, 'from'])
                ->args([param('symfony_security_auditor.audit.fix_synthesis.severity_floor')]),
        ]);
    $defaultsConfigurator->alias(FixSynthesizerInterface::class, FixSynthesizer::class);

    $defaultsConfigurator->set(FixSynthesisStage::class)
        ->args([
            service(FixSynthesizerInterface::class),
            service('logger'),
            param('symfony_security_auditor.audit.fix_synthesis.enabled'),
        ]);

    $defaultsConfigurator->set(NullProgressReporter::class);
    $defaultsConfigurator->set(LoggerProgressReporter::class)
        ->args([service('logger')]);
    $defaultsConfigurator->set(ProgressReporterHolder::class)
        ->args([service('logger')]);
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

    $defaultsConfigurator->set(NullReviewerCache::class);

    $defaultsConfigurator->set(FilesystemReviewerCache::class)
        ->args([
            param('symfony_security_auditor.cache.reviewer_dir'),
            service(Filesystem::class),
            service('logger'),
            param('symfony_security_auditor.cache.reviewer_key_salt'),
            service(ReviewerFeedbackProviderInterface::class),
        ]);

    $defaultsConfigurator->set(SymfonyProcessComposerAuditRunner::class);

    $defaultsConfigurator->set(InMemoryAdvisoryDatabase::class);

    $defaultsConfigurator->set(LockfileHashedAdvisoryCache::class)
        ->args([
            service(SymfonyProcessComposerAuditRunner::class),
            param('symfony_security_auditor.cache.advisory_dir'),
            service(Filesystem::class),
            service('logger'),
            service(ClockInterface::class),
        ]);

    $defaultsConfigurator->set(AuditedProjectPathHolder::class)
        ->args([param('kernel.project_dir')]);

    $defaultsConfigurator->set(DeferredAdvisoryDatabase::class)
        ->args([
            service(ComposerAuditRunnerInterface::class),
            service(AuditedProjectPathHolder::class),
            service('logger'),
        ]);

    $defaultsConfigurator->set(NullStaticPreScanner::class);
    $defaultsConfigurator->set(NullCodeSlicer::class);
    $defaultsConfigurator->set(RegexCodeSlicer::class)
        ->args([param('symfony_security_auditor.audit.code_slicing.min_lines_before_slicing')]);

    $defaultsConfigurator->set(RecordVulnerabilityToolFactory::class);
    $defaultsConfigurator->alias(RecordVulnerabilityToolFactoryInterface::class, RecordVulnerabilityToolFactory::class);

    $defaultsConfigurator->set(RecordReviewToolFactory::class);
    $defaultsConfigurator->alias(RecordReviewToolFactoryInterface::class, RecordReviewToolFactory::class);

    $defaultsConfigurator->set(AttackerAgent::class)
        ->args((new AttackerAgentDefinitionFactory())->args('security_auditor.attacker_client'));

    $defaultsConfigurator->alias(AttackerAgentInterface::class, AttackerAgent::class);

    $defaultsConfigurator->set(ReviewerAgent::class)
        ->args([
            inline_service(ReviewerAgentCollaborators::class)->args([
                service('security_auditor.reviewer_client'),
                service(ReviewerPromptBuilderInterface::class),
                service('logger'),
                service(RecordReviewToolFactoryInterface::class),
                service(ReviewerCacheInterface::class),
                service(ProgressReporterHolder::class),
                service(TriageMemoryRecorderInterface::class),
            ]),
            inline_service(ReviewerModeConfiguration::class)->args([
                param('symfony_security_auditor.audit.reviewer_batch_size'),
                param('symfony_security_auditor.audit.reviewer_tools_enabled'),
                param('symfony_security_auditor.audit.reviewer_max_tool_iterations'),
                param('symfony_security_auditor.audit.reviewer_max_concurrent'),
                param('symfony_security_auditor.audit.reviewer_structured_collection'),
            ]),
            service(ToolRegistryFactoryInterface::class),
        ]);

    $defaultsConfigurator->alias(ReviewerAgentInterface::class, ReviewerAgent::class);

    $defaultsConfigurator->set(EstimateAuditCostUseCase::class)
        ->args([
            service(ProjectFileScannerInterface::class),
            service(TokenEstimatorInterface::class),
            service(CostCalculator::class),
            service('logger'),
            service(FileChunker::class),
            service(AttackerSkillPromptRendererInterface::class),
            param('symfony_security_auditor.attacker_model'),
            param('symfony_security_auditor.audit.max_iterations'),
            EstimateAuditCostUseCase::DEFAULT_OUTPUT_RATIO,
            param('symfony_security_auditor.reviewer_model'),
            EstimateAuditCostUseCase::DEFAULT_REVIEWER_INPUT_RATIO,
            service(GitChangedFilesResolverInterface::class),
            param('symfony_security_auditor.audit.stable_system_prompt'),
            param('symfony_security_auditor.audit.tools_enabled'),
            EstimateAuditCostUseCase::DEFAULT_TOOL_ROUND_TRIP_RATIO,
            param('symfony_security_auditor.audit.max_tool_iterations'),
        ]);

    $defaultsConfigurator->set(ListScannedFilesUseCase::class)
        ->args([
            service(ProjectFileScannerInterface::class),
            service(GitChangedFilesResolverInterface::class),
        ]);

    $defaultsConfigurator->set(RunAuditUseCase::class)
        ->args([
            service(PipelineInterface::class),
            service('logger'),
            service(TokenUsageRecorder::class),
            service(CostCalculator::class),
            param('symfony_security_auditor.attacker_model'),
            service(BudgetTracker::class),
            service(ReviewerFeedbackSnapshotInterface::class)->ignoreOnInvalid(),
        ]);

    $defaultsConfigurator->set(UnpricedModelBudgetGuard::class)
        ->args([
            service(PricingProviderInterface::class),
            param('symfony_security_auditor.audit.models_requiring_pricing'),
            param('symfony_security_auditor.audit.budget.max_cost_usd'),
        ]);
    $defaultsConfigurator->alias(UnpricedModelBudgetGuardInterface::class, UnpricedModelBudgetGuard::class);

    $defaultsConfigurator->set(AuditCommand::class)
        ->args([
            service(RunAuditUseCase::class),
            service(ReportWriterInterface::class),
            service(AuditExitCodeResolverInterface::class),
            service(AuditPresenterInterface::class),
            service(EstimateAuditCostUseCase::class),
            service(ListScannedFilesUseCase::class),
            service(ProgressReporterHolder::class),
            service(AuditedProjectPathHolder::class),
            service(BaselineProcessorInterface::class),
            service(UnpricedModelBudgetGuardInterface::class),
            service(ReviewerFeedbackHolder::class),
            param('symfony_security_auditor.scan.secret_scrubbing.enabled'),
            service(FindingTypeFilterInterface::class),
            param('symfony_security_auditor.config_notices'),
            inline_service(RiskLevel::class)
                ->factory([RiskLevel::class, 'from'])
                ->args([param('symfony_security_auditor.audit.fail_on')]),
            param('symfony_security_auditor.audit.poc_synthesis.enabled'),
            param('symfony_security_auditor.audit.fix_synthesis.enabled'),
        ])
        ->tag('console.command');

    $defaultsConfigurator->set(AuditFailureExitCodeListener::class)
        ->tag('kernel.event_listener', ['event' => 'console.error']);

    $defaultsConfigurator->set(DiffCommand::class)
        ->args([
            service(ReportDifferInterface::class),
            service(DiffPresenterInterface::class),
        ])
        ->tag('console.command');

    $defaultsConfigurator->set(BaselineCommand::class)
        ->args([
            service(BaselineMergerInterface::class),
        ])
        ->tag('console.command');

    $defaultsConfigurator->set(TrendCommand::class)
        ->args([
            service(ReportTrendAnalyzerInterface::class),
            service(TrendPresenterInterface::class),
        ])
        ->tag('console.command');

    $defaultsConfigurator->set(AuditTool::class)
        ->args([
            service(RunAuditUseCase::class),
            service(JsonReportRenderer::class),
            service(AuditedProjectPathHolder::class),
        ]);

    $defaultsConfigurator->set(McpServerFactory::class)
        ->args([
            service(AuditTool::class),
            inline_service(ReportPackage::class),
        ]);
    $defaultsConfigurator->alias(McpServerFactoryInterface::class, McpServerFactory::class);

    $defaultsConfigurator->set(StdioMcpTransportFactory::class);
    $defaultsConfigurator->alias(McpTransportFactoryInterface::class, StdioMcpTransportFactory::class);

    $defaultsConfigurator->set(McpServeCommand::class)
        ->args([
            service(McpServerFactoryInterface::class),
            service(McpTransportFactoryInterface::class),
        ])
        ->tag('console.command');
};
