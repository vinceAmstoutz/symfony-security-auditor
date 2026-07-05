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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullSecurityConfigParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubAnnotationsReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\HtmlReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\MarkdownReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiffer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;

/**
 * Proves `audit:diff` correctly consumes the JSON `audit:run` actually emits,
 * not just hand-crafted fixtures — the two commands must agree on schema.
 */
final class DiffCommandEndToEndTest extends TestCase
{
    private Filesystem $filesystem;

    private string $fixtureDir;

    private string $reportsDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $suffix = uniqid('', true);
        $this->fixtureDir = sys_get_temp_dir().'/diff_e2e_project_'.$suffix;
        $this->reportsDir = sys_get_temp_dir().'/diff_e2e_reports_'.$suffix;
        $this->filesystem->mkdir([$this->fixtureDir.'/src/Controller', $this->reportsDir]);
        $this->filesystem->dumpFile(
            $this->fixtureDir.'/src/Controller/HomeController.php',
            '<?php class HomeController { public function index() {} }',
        );
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->fixtureDir, $this->reportsDir]);
    }

    public function test_it_diffs_the_real_json_reports_produced_by_two_audit_runs(): void
    {
        $persistingFinding = $this->finding('SQL Injection', 'src/Repo1.php');
        $fixedFinding = $this->finding('Hardcoded Secret', 'src/Config1.php');
        $newFinding = $this->finding('Cross-Site Scripting', 'src/View1.php');

        $previousReport = $this->runAuditAndCapture('previous.json', [$persistingFinding, $fixedFinding]);
        $currentReport = $this->runAuditAndCapture('current.json', [$persistingFinding, $newFinding]);

        $diffCommandTester = new CommandTester(new DiffCommand(new ReportDiffer($this->filesystem), new DiffPresenter()));
        $diffCommandTester->execute(['previous-report' => $previousReport, 'current-report' => $currentReport]);

        self::assertSame(Command::SUCCESS, $diffCommandTester->getStatusCode());
        $display = $diffCommandTester->getDisplay();
        self::assertStringContainsString('Cross-Site Scripting', $display);
        self::assertStringContainsString('Hardcoded Secret', $display);
        self::assertStringContainsString('SQL Injection', $display);
        self::assertStringContainsString('Summary: 1 new, 1 fixed, 1 persisting.', $display);
    }

    /**
     * @return array{type: string, title: string, file_path: string}
     */
    private function finding(string $title, string $filePath): array
    {
        return ['type' => 'sql_injection', 'title' => $title, 'file_path' => $filePath];
    }

    /**
     * @param list<array{type: string, title: string, file_path: string}> $findings
     */
    private function runAuditAndCapture(string $reportFilename, array $findings): string
    {
        $attackerPayload = array_map(static fn (array $finding): array => [
            'type' => $finding['type'],
            'severity' => 'critical',
            'title' => $finding['title'],
            'description' => 'Raw query with user input',
            'file_path' => $finding['file_path'],
            'line_start' => 1,
            'line_end' => 5,
            'vulnerable_code' => '$q',
            'attack_vector' => 'Attacker-controlled input reaches a sensitive sink',
            'proof' => "' OR 1=1--",
            'remediation' => 'Use prepared statements',
            'confidence' => 0.95,
        ], $findings);

        $commandTester = $this->makeAuditCommandTester((string) json_encode($attackerPayload), '{"accepted": true}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        preg_match('/(\{.*\})/s', $commandTester->getDisplay(), $matches);

        $reportPath = $this->reportsDir.'/'.$reportFilename;
        $this->filesystem->dumpFile($reportPath, $matches[1] ?? '');

        return $reportPath;
    }

    private function makeAuditCommandTester(string $attackerResponse, string $reviewerResponse): CommandTester
    {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of($attackerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of($reviewerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $progressReporterHolder = new ProgressReporterHolder(new NullLogger());
        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator()), new NullCodeSlicer()),
                new AttackerScanCollaborators(new NullAttackerCache(), new NullStaticPreScanner(), progressReporter: $progressReporterHolder),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLLM,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                    progressReporter: $progressReporterHolder,
                ),
                new ReviewerModeConfiguration(),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
            progressReporter: $progressReporterHolder,
        );
        $auditPipeline = new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
            $progressReporterHolder,
        );

        $projectFileScanner = new ProjectFileScanner(new NullLogger());
        $estimateAuditCostUseCase = new EstimateAuditCostUseCase(
            $projectFileScanner,
            new ResolvingTokenEstimator(),
            new CostCalculator(new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/pricing-catalog.json')),
            new NullLogger(),
            'stub',
            1,
        );
        $auditCommand = new AuditCommand(
            new RunAuditUseCase($auditPipeline, new NullLogger()),
            new ReportWriter([
                new ConsoleReportRenderer(),
                new JsonReportRenderer(),
                new SarifReportRenderer(),
                new HtmlReportRenderer(),
                new MarkdownReportRenderer(),
                new JunitReportRenderer(),
                new GithubAnnotationsReportRenderer(),
            ], new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter(new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/pricing-catalog.json')),
            $estimateAuditCostUseCase,
            new ListScannedFilesUseCase($projectFileScanner),
            $progressReporterHolder,
            new BaselineProcessor(new Baseline(), null),
            new UnpricedModelBudgetGuard(
                new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/pricing-catalog.json'),
                ['stub'],
                null,
            ),
            secretScrubbingEnabled: true,
            findingTypeFilter: new FindingTypeFilter([], []),
        );

        return new CommandTester($auditCommand);
    }
}
