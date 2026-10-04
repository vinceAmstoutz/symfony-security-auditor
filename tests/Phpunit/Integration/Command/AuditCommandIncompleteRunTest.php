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

use JsonException;
use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\NothingAnalyzedPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\PartlyFailedPipeline;

/**
 * A run that reached its end without analyzing every file says so on every
 * output — on stderr when stdout carries the report — and fails with its own
 * exit code only under `--fail-on-incomplete`.
 */
final class AuditCommandIncompleteRunTest extends TestCase
{
    private const string WARNING = 'Audit incomplete: 1 file(s) could not be fully analyzed';

    private const string HINT = 'Pass --fail-on-incomplete to fail the run when this happens.';

    private const string FAILING = 'The run fails because --fail-on-incomplete is set.';

    private string $fixtureDir;

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/audit_cmd_incomplete_'.uniqid('', true);
        mkdir($this->fixtureDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->fixtureDir);
    }

    public function test_an_incomplete_run_passes_with_a_warning_naming_the_flag(): void
    {
        $commandTester = $this->commandTester();

        self::assertSame(Command::SUCCESS, $commandTester->execute(['project-path' => $this->fixtureDir]));
        $display = $this->flattened($commandTester->getDisplay());
        self::assertStringContainsString(self::WARNING, $display);
        self::assertStringContainsString(self::HINT, $display);
    }

    public function test_an_incomplete_run_fails_with_its_own_code_under_the_flag(): void
    {
        $commandTester = $this->commandTester();

        self::assertSame(3, $commandTester->execute(['project-path' => $this->fixtureDir, '--fail-on-incomplete' => true]));
        self::assertStringContainsString(self::FAILING, $this->flattened($commandTester->getDisplay()));
    }

    public function test_a_report_on_stdout_keeps_it_clean_and_warns_on_stderr(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => 'json'], ['capture_stderr_separately' => true]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $decoded = json_decode($commandTester->getDisplay(), true);
        self::assertIsArray($decoded);
        self::assertFalse($decoded['complete'] ?? null);
        $errorOutput = $this->flattened($commandTester->getErrorOutput());
        self::assertStringContainsString(self::WARNING, $errorOutput);
        self::assertStringContainsString(self::HINT, $errorOutput);
    }

    public function test_a_report_on_stdout_fails_under_the_flag_and_says_why_on_stderr(): void
    {
        $commandTester = $this->commandTester();

        $exitCode = $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => 'json', '--fail-on-incomplete' => true], ['capture_stderr_separately' => true]);

        self::assertSame(3, $exitCode);
        self::assertStringContainsString(self::FAILING, $this->flattened($commandTester->getErrorOutput()));
    }

    public function test_a_baseline_generated_from_an_incomplete_run_is_written_with_a_warning(): void
    {
        $commandTester = $this->commandTester();
        $baselineFile = $this->fixtureDir.'/baseline.json';

        self::assertSame(Command::SUCCESS, $commandTester->execute(['project-path' => $this->fixtureDir, '--generate-baseline' => $baselineFile]));
        self::assertFileExists($baselineFile);
        self::assertStringContainsString(self::HINT, $this->flattened($commandTester->getDisplay()));
    }

    public function test_a_baseline_generated_from_an_incomplete_run_fails_under_the_flag(): void
    {
        $commandTester = $this->commandTester();
        $baselineFile = $this->fixtureDir.'/baseline.json';

        self::assertSame(3, $commandTester->execute(['project-path' => $this->fixtureDir, '--generate-baseline' => $baselineFile, '--fail-on-incomplete' => true]));
        self::assertFileExists($baselineFile);
        self::assertStringContainsString(self::FAILING, $this->flattened($commandTester->getDisplay()));
    }

    /**
     * @throws JsonException
     */
    public function test_a_run_with_no_verdict_leaves_the_existing_baseline_untouched_and_fails(): void
    {
        $baselineFile = $this->fixtureDir.'/baseline.json';
        $baseline = json_encode([[
            'fingerprint' => 'SSA-0123456789AB',
            'type' => 'sql_injection',
            'file' => 'src/Failed.php',
            'title' => 'Accepted query',
            'added_at' => '2026-01-01T00:00:00+00:00',
            'reason' => 'Parameters are bound by the repository',
        ]], \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR);
        file_put_contents($baselineFile, $baseline);
        $reportFile = $this->fixtureDir.'/report.json';
        $commandTester = $this->commandTester(new NothingAnalyzedPipeline());

        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $baselineFile,
            '--format' => 'json',
            '--output' => $reportFile,
        ]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringEqualsFile($baselineFile, $baseline);
        self::assertFileExists($reportFile);
        self::assertStringContainsString(
            \sprintf('Audit incomplete: none of the 1 file(s) in scope could be analyzed, so the run has no verdict. The baseline at %s was left as it was: a run with no verdict cannot replace the accepted findings, so it fails.', $baselineFile),
            $this->flattened($commandTester->getDisplay()),
        );
    }

    public function test_a_run_whose_scan_found_no_file_writes_no_baseline_and_fails(): void
    {
        $baselineFile = $this->fixtureDir.'/baseline.json';
        $commandTester = $this->commandTester(self::createStub(PipelineInterface::class));

        self::assertSame(Command::FAILURE, $commandTester->execute(['project-path' => $this->fixtureDir, '--generate-baseline' => $baselineFile]));
        self::assertFileDoesNotExist($baselineFile);
        self::assertStringContainsString('The scan found no file to audit, so the run has no verdict.', $this->flattened($commandTester->getDisplay()));
    }

    private function flattened(string $output): string
    {
        return (string) preg_replace('/\s+/', ' ', $output);
    }

    private function commandTester(PipelineInterface $pipeline = new PartlyFailedPipeline()): CommandTester
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/../UseCase/Fixture/pricing-catalog.json');
        $projectFileScanner = new ProjectFileScanner(new NullLogger());

        return new CommandTester(new AuditCommand(
            new RunAuditUseCase($pipeline, new NullLogger()),
            new ReportWriter([new ConsoleReportRenderer(), new JsonReportRenderer()], new Filesystem()),
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
