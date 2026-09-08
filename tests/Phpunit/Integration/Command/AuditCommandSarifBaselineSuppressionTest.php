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
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SecurityAuditor\Command\Baseline;
use VinceAmstoutz\SecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SecurityAuditor\Command\Exception\UnsafeBaselineWriteException;
use VinceAmstoutz\SecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SymfonySkillSet;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyProjectFileTypeClassifier;
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
     * @throws MalformedBaselineFileException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws UnsafeBaselineWriteException
     */
    public function test_sarif_format_renders_a_baselined_finding_with_a_suppression_entry(): void
    {
        $vulnerability = $this->makeVuln();
        $baselineFile = $this->fixtureDir.'/baseline.json';
        (new Baseline())->save($baselineFile, [['fingerprint' => $vulnerability->fingerprint()]]);

        $commandTester = $this->makeCommandTester($vulnerability);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'sarif',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());

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
     * @throws MalformedBaselineFileException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws UnsafeBaselineWriteException
     */
    public function test_json_format_still_drops_the_same_baselined_finding(): void
    {
        $vulnerability = $this->makeVuln();
        $baselineFile = $this->fixtureDir.'/baseline.json';
        (new Baseline())->save($baselineFile, [['fingerprint' => $vulnerability->fingerprint()]]);

        $commandTester = $this->makeCommandTester($vulnerability);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'json',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());

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

    private function makeCommandTester(Vulnerability $vulnerability): CommandTester
    {
        $pricingCatalog = __DIR__.'/../UseCase/Fixture/pricing-catalog.json';
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), $pricingCatalog);
        $projectFileScanner = new ProjectFileScanner(new SymfonyProjectFileTypeClassifier(), new NullLogger());

        $auditCommand = new AuditCommand(
            new RunAuditUseCase(new FixedFindingPipeline($vulnerability), new NullLogger()),
            new ReportWriter([new JsonReportRenderer(), new SarifReportRenderer()], new Filesystem()),
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
