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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\IngestedThenAnalyzedPipeline;

/**
 * A file the scan leaves out for its size is listed in the report's coverage
 * and gates nothing: the run is as complete, and exits as it did when such a
 * file was dropped without a trace.
 */
final class AuditCommandSkippedFilesTest extends TestCase
{
    private string $projectDir;

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/audit_cmd_skipped_'.uniqid('', true);
        mkdir($this->projectDir.'/src', 0o777, true);
        file_put_contents($this->projectDir.'/src/Small.php', '<?php class Small {}');
        file_put_contents($this->projectDir.'/src/Big.php', str_repeat('a', 1024 + 1));
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectDir);
    }

    public function test_a_file_over_the_size_limit_does_not_fail_a_run_under_fail_on_incomplete(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(['project-path' => $this->projectDir, '--fail-on-incomplete' => true]);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringNotContainsString('Audit incomplete', $commandTester->getDisplay());
    }

    public function test_a_file_over_the_size_limit_is_listed_in_the_json_coverage_of_a_complete_report(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(['project-path' => $this->projectDir, '--format' => 'json', '--fail-on-incomplete' => true], ['capture_stderr_separately' => true]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $decoded = json_decode($commandTester->getDisplay(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertTrue($decoded['complete']);
        self::assertSame(
            [
                ['stage' => 'scan', 'file' => 'src/Big.php', 'status' => 'skipped'],
                ['stage' => 'attacker', 'file' => 'src/Small.php', 'status' => 'analyzed'],
            ],
            $decoded['coverage'],
        );
    }

    public function test_a_file_over_the_size_limit_leaves_sarif_execution_successful(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(['project-path' => $this->projectDir, '--format' => 'sarif'], ['capture_stderr_separately' => true]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $decoded = json_decode($commandTester->getDisplay(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        $runs = $decoded['runs'];
        self::assertIsArray($runs);
        $run = $runs[0];
        self::assertIsArray($run);
        self::assertSame([['executionSuccessful' => true]], $run['invocations']);
    }

    private function commandTester(): CommandTester
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/../UseCase/Fixture/pricing-catalog.json');
        $projectFileScanner = new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 1);
        $ingestedThenAnalyzedPipeline = new IngestedThenAnalyzedPipeline(new IngestionStage($projectFileScanner, new NullLogger()));

        return new CommandTester(new AuditCommand(
            new RunAuditUseCase($ingestedThenAnalyzedPipeline, new NullLogger()),
            new ReportWriter([new ConsoleReportRenderer(), new JsonReportRenderer(), new SarifReportRenderer()], new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter($modelsDevPricingProvider),
            new EstimateAuditCostUseCase($projectFileScanner, new ResolvingTokenEstimator(), new CostCalculator($modelsDevPricingProvider), new NullLogger(), new FileChunker(), new AttackerSkillRegistry(), 'stub', 1),
            new ListScannedFilesUseCase($projectFileScanner),
            new ProgressReporterHolder(new NullLogger()),
            new AuditedProjectPathHolder('/app'),
            new BaselineProcessor(new Baseline()),
            new UnpricedModelBudgetGuard($modelsDevPricingProvider, ['stub']),
            new ReviewerFeedbackHolder(),
            secretScrubbingEnabled: true,
            findingTypeFilter: new FindingTypeFilter([], []),
        ));
    }
}
