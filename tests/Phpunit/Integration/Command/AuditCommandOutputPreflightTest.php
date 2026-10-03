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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ExitCode;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;

/**
 * An `--output` path the report could never be saved to is refused before the
 * pipeline runs, so the audit spends nothing on a report that would be lost.
 */
final class AuditCommandOutputPreflightTest extends TestCase
{
    private string $fixtureDir;

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/audit_cmd_output_preflight_'.uniqid('', true);
        mkdir($this->fixtureDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->fixtureDir);
    }

    public function test_an_output_path_beneath_a_regular_file_aborts_before_the_pipeline_runs(): void
    {
        $blockingFile = $this->fixtureDir.'/blocking';
        (new Filesystem())->dumpFile($blockingFile, 'x');
        $commandTester = $this->makeCommandTester();

        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
            '--output' => $blockingFile.'/report.json',
        ]);

        self::assertSame(ExitCode::Failure->value, $exitCode);
        self::assertStringContainsString('before the audit spends anything', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }

    public function test_a_symlinked_output_path_aborts_before_the_pipeline_runs(): void
    {
        symlink($this->fixtureDir.'/elsewhere.json', $this->fixtureDir.'/report.json');
        $commandTester = $this->makeCommandTester();

        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
            '--output' => $this->fixtureDir.'/report.json',
        ]);

        self::assertSame(ExitCode::Failure->value, $exitCode);
        self::assertStringContainsString('symlink', $commandTester->getDisplay());
    }

    public function test_an_output_path_naming_a_directory_aborts_before_the_pipeline_runs(): void
    {
        $commandTester = $this->makeCommandTester();

        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
            '--output' => $this->fixtureDir.'/reports/',
        ]);

        self::assertSame(ExitCode::Failure->value, $exitCode);
        self::assertStringContainsString('names a directory', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }

    public function test_a_symlinked_baseline_path_aborts_before_the_pipeline_runs(): void
    {
        symlink($this->fixtureDir.'/elsewhere.json', $this->fixtureDir.'/.security-baseline.json');
        $commandTester = $this->makeCommandTester();

        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $this->fixtureDir.'/.security-baseline.json',
        ]);

        self::assertSame(ExitCode::Failure->value, $exitCode);
        self::assertStringContainsString('Refusing to write baseline through symlinked path', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }

    public function test_a_baseline_path_through_a_symlinked_directory_of_the_project_aborts_before_the_pipeline_runs(): void
    {
        $filesystem = new Filesystem();
        $outsideDir = sys_get_temp_dir().'/audit_cmd_output_preflight_outside_'.uniqid('', true);
        $filesystem->mkdir($outsideDir);
        symlink($outsideDir, $this->fixtureDir.'/security');
        $commandTester = $this->makeCommandTester();

        try {
            $exitCode = $commandTester->execute([
                'project-path' => $this->fixtureDir,
                '--generate-baseline' => $this->fixtureDir.'/security/baselines/baseline.json',
            ]);

            self::assertSame(ExitCode::Failure->value, $exitCode);
            self::assertStringContainsString('Refusing to write baseline through symlinked path', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
            self::assertDirectoryDoesNotExist($outsideDir.'/baselines');
        } finally {
            $filesystem->remove($outsideDir);
        }
    }

    public function test_a_baseline_path_naming_a_directory_aborts_before_the_pipeline_runs(): void
    {
        $commandTester = $this->makeCommandTester();

        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $this->fixtureDir.'/baselines/',
        ]);

        self::assertSame(ExitCode::Failure->value, $exitCode);
        self::assertStringContainsString('before the audit spends anything', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }

    private function makeCommandTester(): CommandTester
    {
        $pipeline = $this->createMock(PipelineInterface::class);
        $pipeline->expects(self::never())->method('process');
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/../UseCase/Fixture/pricing-catalog.json');
        $projectFileScanner = new ProjectFileScanner(new NullLogger());

        $auditCommand = new AuditCommand(
            new RunAuditUseCase($pipeline, new NullLogger()),
            new ReportWriter([new JsonReportRenderer()], new Filesystem()),
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
            findingTypeFilter: new FindingTypeFilter(),
        );

        return new CommandTester($auditCommand);
    }
}
