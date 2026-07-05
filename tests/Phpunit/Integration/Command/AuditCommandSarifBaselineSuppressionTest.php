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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\FixedFindingPipeline;

/**
 * Drives {@see AuditCommand} with a fixed, already-validated finding injected
 * directly into the pipeline (bypassing the attacker/reviewer loop, whose own
 * baseline handling is covered by AuditOrchestratorTest), to verify the
 * command's SARIF-specific baseline-suppression wiring in isolation.
 */
final class AuditCommandSarifBaselineSuppressionTest extends TestCase
{
    private string $fixtureDir;

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/audit_cmd_sarif_baseline_'.uniqid('', true);
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
     */
    public function test_sarif_format_renders_a_baselined_finding_with_a_suppression_entry(): void
    {
        $vulnerability = $this->makeVuln();
        $baselineFile = $this->fixtureDir.'/baseline.json';
        (new Baseline())->save($baselineFile, [$vulnerability->fingerprint()]);

        $commandTester = $this->makeCommandTester($vulnerability);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'sarif',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());

        $decoded = json_decode($commandTester->getDisplay(), true);
        self::assertIsArray($decoded);
        $runs = $decoded['runs'] ?? null;
        self::assertIsArray($runs);
        $firstRun = $runs[0] ?? null;
        self::assertIsArray($firstRun);
        $results = $firstRun['results'] ?? null;
        self::assertIsArray($results);
        $firstResult = $results[0] ?? null;
        self::assertIsArray($firstResult);

        self::assertCount(1, $results);
        self::assertSame(
            [['kind' => 'external', 'justification' => 'Accepted via audit baseline']],
            $firstResult['suppressions'] ?? null,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_json_format_still_drops_the_same_baselined_finding(): void
    {
        $vulnerability = $this->makeVuln();
        $baselineFile = $this->fixtureDir.'/baseline.json';
        (new Baseline())->save($baselineFile, [$vulnerability->fingerprint()]);

        $commandTester = $this->makeCommandTester($vulnerability);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'json',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());

        $decoded = json_decode($commandTester->getDisplay(), true);
        self::assertIsArray($decoded);
        self::assertSame(0, $decoded['total_vulnerabilities'] ?? null);
        self::assertSame([], $decoded['vulnerabilities'] ?? null);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    private function makeVuln(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Critical SQL Injection', 0.95),
            new CodeLocation('src/Repo.php', 1, 5),
            new VulnerabilityNarrative('Raw query with user input', 'SQL injection via query param', "' OR 1=1--", 'Use prepared statements'),
            '$q',
        )->withReviewerValidation(true);
    }

    private function makeCommandTester(Vulnerability $vulnerability): CommandTester
    {
        $pricingCatalog = __DIR__.'/../UseCase/Fixture/pricing-catalog.json';
        $pricingProvider = new ModelsDevPricingProvider(new NullLogger(), $pricingCatalog);
        $projectFileScanner = new ProjectFileScanner(new NullLogger());

        $auditCommand = new AuditCommand(
            new RunAuditUseCase(new FixedFindingPipeline($vulnerability), new NullLogger()),
            new ReportWriter([new JsonReportRenderer(), new SarifReportRenderer()], new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter($pricingProvider),
            new EstimateAuditCostUseCase($projectFileScanner, new ResolvingTokenEstimator(), new CostCalculator($pricingProvider), new NullLogger(), 'stub', 1),
            new ListScannedFilesUseCase($projectFileScanner),
            new ProgressReporterHolder(new NullLogger()),
            new BaselineProcessor(new Baseline()),
            new UnpricedModelBudgetGuard($pricingProvider, ['stub']),
            secretScrubbingEnabled: true,
            findingTypeFilter: new FindingTypeFilter([], []),
        );

        return new CommandTester($auditCommand);
    }
}
