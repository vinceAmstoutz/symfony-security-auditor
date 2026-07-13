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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestratorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\FixSynthesizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\FixSynthesizerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\PoCSynthesizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\PoCSynthesizerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\FixSynthesisStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\PoCSynthesisStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecurityConfigParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\VoterCapabilityParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\DeferredAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHashedAdvisoryCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AttackerAgentDefinitionFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Diff\ProcessGitChangedFilesResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\BackoffSchedule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\AnthropicTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\CharacterRatioCounter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\DeepSeekTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\GeminiTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\LlamaTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\MistralTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\OpenAiTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ProviderTokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\LoggerProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSections;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSectionsInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ApiResourceAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AuthenticatorAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerFileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EntityAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EntityFileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EventSubscriberAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FormAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\LiveComponentAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\MessengerHandlerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\NormalizerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SchedulerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TemplateAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TwigExtensionAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\VoterAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\WebhookConsumerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubAnnotationsReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\HtmlReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\MarkdownReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\SymfonyToolRegistryFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineMerger;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineMergerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffPresenterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiffer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDifferInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoaderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportTrendAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportTrendAnalyzerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendHtmlRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendHtmlRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendPresenterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuardInterface;

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
        ->args([service('logger')]);
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
    $defaultsConfigurator->set(ResolvingTokenEstimator::class)
        ->args([tagged_iterator('symfony_security_auditor.token_estimator')]);
    $defaultsConfigurator->alias(TokenEstimatorInterface::class, ResolvingTokenEstimator::class);

    $defaultsConfigurator->set(UsleepSleeper::class);
    $defaultsConfigurator->alias(SleeperInterface::class, UsleepSleeper::class);

    $defaultsConfigurator->set(NullSecretScrubber::class);

    // `SecretScrubberInterface` alias is set in SymfonySecurityAuditorBundle::loadExtension()
    // based on `scan.secret_scrubbing.enabled`.
    $defaultsConfigurator->set(RegexSecretScrubber::class)
        ->args([param('symfony_security_auditor.scan.secret_scrubbing.additional_patterns')]);

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
    $defaultsConfigurator->set(ApiResourceAttackerSkill::class);
    $defaultsConfigurator->set(AuthenticatorAttackerSkill::class);
    $defaultsConfigurator->set(ConfigAttackerSkill::class);
    $defaultsConfigurator->set(ControllerAttackerSkill::class);
    $defaultsConfigurator->set(ControllerFileUploadAttackerSkill::class);
    $defaultsConfigurator->set(EntityAttackerSkill::class);
    $defaultsConfigurator->set(EntityFileUploadAttackerSkill::class);
    $defaultsConfigurator->set(EventSubscriberAttackerSkill::class);
    $defaultsConfigurator->set(FileUploadAttackerSkill::class);
    $defaultsConfigurator->set(FormAttackerSkill::class);
    $defaultsConfigurator->set(LiveComponentAttackerSkill::class);
    $defaultsConfigurator->set(MessengerHandlerAttackerSkill::class);
    $defaultsConfigurator->set(NormalizerAttackerSkill::class);
    $defaultsConfigurator->set(PhpAttackerSkill::class);
    $defaultsConfigurator->set(RepositoryAttackerSkill::class);
    $defaultsConfigurator->set(SchedulerAttackerSkill::class);
    $defaultsConfigurator->set(TemplateAttackerSkill::class);
    $defaultsConfigurator->set(TwigExtensionAttackerSkill::class);
    $defaultsConfigurator->set(VoterAttackerSkill::class);
    $defaultsConfigurator->set(WebhookConsumerAttackerSkill::class);
    $defaultsConfigurator->set(AttackerSkillRegistry::class)
        ->args([tagged_iterator('symfony_security_auditor.attacker_skill')]);

    $defaultsConfigurator->set(AttackerPromptBuilder::class)
        ->args([
            param('symfony_security_auditor.audit.structured_collection'),
            param('symfony_security_auditor.audit.stable_system_prompt'),
            service(AttackerSkillRegistry::class),
        ]);
    $defaultsConfigurator->alias(AttackerPromptBuilderInterface::class, AttackerPromptBuilder::class);

    $defaultsConfigurator->set(ReviewerPromptSections::class);
    $defaultsConfigurator->alias(ReviewerPromptSectionsInterface::class, ReviewerPromptSections::class);
    $defaultsConfigurator->set(ReviewerMessageRenderer::class);
    $defaultsConfigurator->alias(ReviewerMessageRendererInterface::class, ReviewerMessageRenderer::class);

    $defaultsConfigurator->set(ReviewerFeedbackHolder::class);
    $defaultsConfigurator->alias(ReviewerFeedbackProviderInterface::class, ReviewerFeedbackHolder::class);

    $defaultsConfigurator->set(ReviewerPromptBuilder::class)
        ->args([
            param('symfony_security_auditor.audit.reviewer_structured_collection'),
            service(ReviewerPromptSectionsInterface::class),
            service(ReviewerMessageRendererInterface::class),
            service(ReviewerFeedbackProviderInterface::class),
        ]);
    $defaultsConfigurator->alias(ReviewerPromptBuilderInterface::class, ReviewerPromptBuilder::class);

    $defaultsConfigurator->set(ConsoleReportRenderer::class);
    $defaultsConfigurator->set(JsonReportRenderer::class);
    $defaultsConfigurator->set(SarifReportRenderer::class);
    $defaultsConfigurator->set(HtmlReportRenderer::class);
    $defaultsConfigurator->set(MarkdownReportRenderer::class);
    $defaultsConfigurator->set(JunitReportRenderer::class);
    $defaultsConfigurator->set(GithubAnnotationsReportRenderer::class);

    $defaultsConfigurator->set(ReportWriter::class)
        ->args([tagged_iterator('symfony_security_auditor.report_renderer')]);
    $defaultsConfigurator->alias(ReportWriterInterface::class, ReportWriter::class);

    $defaultsConfigurator->set(AuditExitCodeResolver::class);
    $defaultsConfigurator->alias(AuditExitCodeResolverInterface::class, AuditExitCodeResolver::class);

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

    $defaultsConfigurator->set(PhpParserControllerAccessControlParser::class);
    $defaultsConfigurator->alias(ControllerAccessControlParserInterface::class, PhpParserControllerAccessControlParser::class);

    $defaultsConfigurator->set(PhpParserVoterCapabilityParser::class);
    $defaultsConfigurator->alias(VoterCapabilityParserInterface::class, PhpParserVoterCapabilityParser::class);

    $defaultsConfigurator->set(PhpParserFormBindingParser::class);
    $defaultsConfigurator->alias(FormBindingParserInterface::class, PhpParserFormBindingParser::class);

    $defaultsConfigurator->set(SymfonyYamlSecurityConfigParser::class)
        ->args([service('logger')]);
    $defaultsConfigurator->alias(SecurityConfigParserInterface::class, SymfonyYamlSecurityConfigParser::class);

    $defaultsConfigurator->set(MappingStage::class)
        ->args([
            service('logger'),
            service(ControllerAccessControlParserInterface::class),
            service(VoterCapabilityParserInterface::class),
            service(FormBindingParserInterface::class),
            service(SecurityConfigParserInterface::class),
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
            param('symfony_security_auditor.attacker_model'),
            param('symfony_security_auditor.audit.max_iterations'),
            EstimateAuditCostUseCase::DEFAULT_OUTPUT_RATIO,
            param('symfony_security_auditor.reviewer_model'),
            EstimateAuditCostUseCase::DEFAULT_REVIEWER_INPUT_RATIO,
            service(GitChangedFilesResolverInterface::class),
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
        ])
        ->tag('console.command');

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
};
