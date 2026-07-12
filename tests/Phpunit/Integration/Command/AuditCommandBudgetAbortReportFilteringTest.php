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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
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
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ExitCode;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\BudgetAbortingPipeline;

/**
 * Drives {@see AuditCommand} with a pipeline that adds one already-validated
 * finding and then throws `BudgetExceededException`, to verify the partial
 * report `handleBudgetAbort()` writes is shaped by the same finding-type
 * filter and baseline suppression a completed run applies — not written out
 * raw.
 */
final class AuditCommandBudgetAbortReportFilteringTest extends TestCase
{
    private string $fixtureDir;

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/audit_cmd_budget_abort_'.uniqid('', true);
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
    public function test_partial_report_on_budget_abort_excludes_a_configured_finding_type(): void
    {
        $vulnerability = $this->makeVuln();

        $commandTester = $this->makeCommandTester($vulnerability, excludedTypes: [VulnerabilityType::SQL_INJECTION->value]);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

        $output = $commandTester->getDisplay();
        preg_match('/(\{.*\})/s', $output, $matches);
        $decoded = json_decode($matches[1] ?? '', true);
        self::assertIsArray($decoded);
        self::assertSame(0, $decoded['total_vulnerabilities'] ?? null);
        self::assertSame([], $decoded['vulnerabilities'] ?? null);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws MalformedBaselineFileException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws UnsafeBaselineWriteException
     */
    public function test_partial_report_on_budget_abort_drops_a_baselined_finding(): void
    {
        $vulnerability = $this->makeVuln();
        $baselineFile = $this->fixtureDir.'/baseline.json';
        (new Baseline())->save($baselineFile, [['fingerprint' => $vulnerability->fingerprint()]]);

        $commandTester = $this->makeCommandTester($vulnerability, configuredBaseline: $baselineFile);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'json',
        ]);

        $output = $commandTester->getDisplay();
        preg_match('/(\{.*\})/s', $output, $matches);
        $decoded = json_decode($matches[1] ?? '', true);
        self::assertIsArray($decoded);
        self::assertSame(0, $decoded['total_vulnerabilities'] ?? null);
        self::assertSame([], $decoded['vulnerabilities'] ?? null);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws MalformedBaselineFileException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws UnsafeBaselineWriteException
     */
    public function test_partial_report_on_budget_abort_renders_a_baselined_finding_as_suppressed_in_sarif(): void
    {
        $vulnerability = $this->makeVuln();
        $baselineFile = $this->fixtureDir.'/baseline.json';
        (new Baseline())->save($baselineFile, [['fingerprint' => $vulnerability->fingerprint()]]);

        $commandTester = $this->makeCommandTester($vulnerability, configuredBaseline: $baselineFile);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'sarif',
        ]);

        $output = $commandTester->getDisplay();
        preg_match('/(\{.*\})/s', $output, $matches);
        $decoded = json_decode($matches[1] ?? '', true);
        self::assertIsArray($decoded);
        $runs = $decoded['runs'] ?? null;
        self::assertIsArray($runs);
        $firstRun = $runs[0] ?? null;
        self::assertIsArray($firstRun);
        $results = $firstRun['results'] ?? null;
        self::assertIsArray($results);
        self::assertCount(1, $results);
        $firstResult = $results[0] ?? null;
        self::assertIsArray($firstResult);
        self::assertSame(
            [['kind' => 'external', 'justification' => 'Accepted via audit baseline']],
            $firstResult['suppressions'] ?? null,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_malformed_baseline_file_during_a_budget_abort_is_reported_as_a_graceful_error_instead_of_crashing(): void
    {
        $vulnerability = $this->makeVuln();
        $baselineFile = $this->fixtureDir.'/baseline.json';
        file_put_contents($baselineFile, 'not valid json{{{');

        $commandTester = $this->makeCommandTester($vulnerability, configuredBaseline: $baselineFile);
        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'sarif',
        ]);

        self::assertSame(ExitCode::Failure->value, $exitCode);
        self::assertStringContainsString('Unexpected error', $commandTester->getDisplay());
        self::assertStringContainsString('Syntax error', $commandTester->getDisplay());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
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

    /**
     * @param list<string> $excludedTypes
     */
    private function makeCommandTester(Vulnerability $vulnerability, array $excludedTypes = [], ?string $configuredBaseline = null): CommandTester
    {
        $pricingCatalog = __DIR__.'/../UseCase/Fixture/pricing-catalog.json';
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), $pricingCatalog);
        $projectFileScanner = new ProjectFileScanner(new NullLogger());

        $auditCommand = new AuditCommand(
            new RunAuditUseCase(new BudgetAbortingPipeline($vulnerability), new NullLogger()),
            new ReportWriter([new JsonReportRenderer(), new SarifReportRenderer()], new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter($modelsDevPricingProvider),
            new EstimateAuditCostUseCase($projectFileScanner, new ResolvingTokenEstimator(), new CostCalculator($modelsDevPricingProvider), new NullLogger(), 'stub', 1),
            new ListScannedFilesUseCase($projectFileScanner),
            new ProgressReporterHolder(new NullLogger()),
            new AuditedProjectPathHolder('/app'),
            new BaselineProcessor(new Baseline(), $configuredBaseline),
            new UnpricedModelBudgetGuard($modelsDevPricingProvider, ['stub']),
            secretScrubbingEnabled: true,
            findingTypeFilter: new FindingTypeFilter([], $excludedTypes),
        );

        return new CommandTester($auditCommand);
    }
}
