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
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Feedback\ReviewerFeedbackHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SecurityAuditor\Command\Baseline;
use VinceAmstoutz\SecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SecurityAuditor\Command\ExitCode;
use VinceAmstoutz\SecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SymfonySkillSet;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyProjectFileTypeClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\FixedFindingPipeline;

/**
 * `--generate-baseline` needs real findings from a real audit run, but
 * `--dry-run`/`--show-scanned` both exit before the LLM (and therefore the
 * pipeline `FixedFindingPipeline` stands in for here) is ever invoked —
 * verifies the combination is rejected instead of the baseline file silently
 * never being written.
 */
final class AuditCommandConflictingOptionsTest extends TestCase
{
    private string $fixtureDir;

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/audit_cmd_conflicting_options_'.uniqid('', true);
        mkdir($this->fixtureDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->fixtureDir);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_generate_baseline_combined_with_dry_run_fails_instead_of_silently_skipping_the_baseline_file(): void
    {
        $baselineFile = $this->fixtureDir.'/baseline.json';

        $commandTester = $this->makeCommandTester();
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--dry-run' => true,
            '--generate-baseline' => $baselineFile,
        ]);

        self::assertSame(ExitCode::AuditFailed->value, $commandTester->getStatusCode());
        self::assertFileDoesNotExist($baselineFile);
        self::assertStringContainsString('--generate-baseline', $commandTester->getDisplay());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_generate_baseline_combined_with_show_scanned_fails_instead_of_silently_skipping_the_baseline_file(): void
    {
        $baselineFile = $this->fixtureDir.'/baseline.json';

        $commandTester = $this->makeCommandTester();
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--show-scanned' => true,
            '--generate-baseline' => $baselineFile,
        ]);

        self::assertSame(ExitCode::AuditFailed->value, $commandTester->getStatusCode());
        self::assertFileDoesNotExist($baselineFile);
        self::assertStringContainsString('--generate-baseline', $commandTester->getDisplay());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_dry_run_does_not_warn_about_synthesis_cost_by_default(): void
    {
        $commandTester = $this->makeCommandTester();
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--dry-run' => true,
        ]);

        self::assertStringNotContainsString('synthesis', $commandTester->getDisplay());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeCommandTester(): CommandTester
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Critical SQL Injection', 0.95),
            new CodeLocation('src/Repo.php', 1, 5),
            new VulnerabilityNarrative('Raw query with user input', 'SQL injection via query param', "' OR 1=1--", 'Use prepared statements'),
            '$q',
        )->withReviewerValidation(true);

        $pricingCatalog = __DIR__.'/../UseCase/Fixture/pricing-catalog.json';
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), $pricingCatalog);
        $projectFileScanner = new ProjectFileScanner(new SymfonyProjectFileTypeClassifier(), new NullLogger());

        $auditCommand = new AuditCommand(
            new RunAuditUseCase(new FixedFindingPipeline($vulnerability), new NullLogger()),
            new ReportWriter([new JsonReportRenderer()], new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter($modelsDevPricingProvider),
            new EstimateAuditCostUseCase($projectFileScanner, new ResolvingTokenEstimator(), new CostCalculator($modelsDevPricingProvider), new NullLogger(), new FileChunker(), new AttackerSkillRegistry(SymfonySkillSet::all()), 'stub', 1),
            new ListScannedFilesUseCase($projectFileScanner),
            new ProgressReporterHolder(new NullLogger()),
            new AuditedProjectPathHolder('/app'),
            new BaselineProcessor(new Baseline()),
            new UnpricedModelBudgetGuard($modelsDevPricingProvider, ['stub']),
            new ReviewerFeedbackHolder(),
            secretScrubbingEnabled: true,
            findingTypeFilter: new FindingTypeFilter([], []),
        );

        return new CommandTester($auditCommand);
    }
}
