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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp;

use Mcp\Exception\ToolCallException;
use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\AuditWithoutVerdictException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnenforceableBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\AuditTool;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuardInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture\PartlyFailedPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp\Fixture\SingleFileAuditPipeline;

final class AuditToolTest extends TestCase
{
    private string $projectPath;

    #[Override]
    protected function setUp(): void
    {
        $this->projectPath = sys_get_temp_dir().'/ssa-mcp-audit-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->projectPath);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectPath);
    }

    /**
     * @throws ToolCallException
     */
    public function test_it_audits_the_given_path_and_returns_the_rendered_json_report(): void
    {
        $auditTool = $this->auditTool();

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertSame($this->projectPath, $report['project']);
    }

    /**
     * @throws ToolCallException
     */
    public function test_it_returns_the_report_as_rendered_by_the_report_renderer(): void
    {
        $renderer = self::createStub(ReportRendererInterface::class);
        $renderer->method('render')->willReturn('RENDERED-REPORT');

        $auditTool = $this->auditTool(reportRenderer: $renderer);

        self::assertSame('RENDERED-REPORT', $auditTool->audit($this->projectPath));
    }

    /**
     * `ComposerAuditAdvisoryDatabase`, `SarifImportingPreScanner` and
     * `FilesystemTriageMemoryStore` all resolve the audited project through
     * `AuditedProjectPathHolder::path()`, which falls back to the bundle's own
     * `kernel.project_dir` when never `set()`. `AuditCommand` sets it from the
     * resolved CLI argument before running; the MCP entrypoint must do the
     * same for its own `path` argument, or those collaborators silently
     * resolve against the wrong project when the tool is invoked over MCP.
     *
     * @throws ToolCallException
     */
    public function test_it_sets_the_audited_project_path_holder_before_running_the_use_case(): void
    {
        $auditedProjectPathHolder = $this->auditedProjectPathHolder();
        $auditTool = $this->auditTool(auditedProjectPathHolder: $auditedProjectPathHolder);

        $auditTool->audit($this->projectPath);

        self::assertSame($this->projectPath, $auditedProjectPathHolder->path());
    }

    /**
     * The MCP tool's own JSON schema documents `path` as "Absolute path to
     * the Symfony project directory to audit" but nothing enforced that
     * contract — unlike `AuditCommandInput::resolvedProjectPath()`, which
     * resolves a relative CLI argument against a known working directory.
     * An MCP tool call has no equivalent "current directory" concept to fall
     * back to, so a relative `path` is rejected rather than silently
     * resolved against the server process's own cwd.
     *
     * @throws ToolCallException
     */
    public function test_it_rejects_a_non_absolute_path(): void
    {
        $auditTool = $this->auditTool();

        try {
            $auditTool->audit('relative/path');
            self::fail('A relative path must be refused.');
        } catch (ToolCallException $toolCallException) {
            self::assertStringContainsString('must be absolute', $toolCallException->getMessage());
            self::assertInstanceOf(InvalidProjectPathException::class, $toolCallException->getPrevious());
        }
    }

    /**
     * `AuditCommandInput::resolvedProjectPath()` canonicalizes an absolute
     * CLI argument via `Path::canonicalize()` before anything downstream
     * sees it; `AuditTool` must do the same for its own `path` argument so a
     * `..`-bearing MCP path resolves identically to the CLI path, keeping
     * `AuditedProjectPathHolder::path()` a stable cache/lookup key regardless
     * of entry point.
     *
     * @throws ToolCallException
     */
    public function test_it_canonicalizes_the_path_before_setting_the_holder_and_running(): void
    {
        $auditedProjectPathHolder = $this->auditedProjectPathHolder();
        $auditTool = $this->auditTool(auditedProjectPathHolder: $auditedProjectPathHolder);

        $auditTool->audit($this->projectPath.'/nested/..');

        self::assertSame($this->projectPath, $auditedProjectPathHolder->path());
    }

    public function test_it_refuses_a_budgeted_run_on_an_unpriced_model_before_any_llm_call(): void
    {
        $pipeline = $this->createMock(PipelineInterface::class);
        $pipeline->expects(self::never())->method('process');
        $auditTool = $this->budgetedAuditTool($this->budgetGuard(10.0, ['priced-model', 'mystery-model']), $pipeline);

        try {
            $auditTool->audit($this->projectPath);
            self::fail('A budgeted run on an unpriced model must be refused.');
        } catch (ToolCallException $toolCallException) {
            self::assertSame(
                'Refusing to start a budgeted audit with an unpriceable model in non-interactive mode. Configure a model with published pricing, or remove audit.budget.max_cost_usd. Unpriced model(s): mystery-model.',
                $toolCallException->getMessage(),
            );
            self::assertInstanceOf(UnenforceableBudgetException::class, $toolCallException->getPrevious());
        }
    }

    /**
     * @throws ToolCallException
     */
    public function test_it_runs_a_budgeted_audit_when_every_model_is_priced(): void
    {
        $auditTool = $this->budgetedAuditTool($this->budgetGuard(10.0, ['priced-model']));

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertSame($this->projectPath, $report['project']);
    }

    /**
     * @throws ToolCallException
     */
    public function test_it_runs_an_unbudgeted_audit_on_an_unpriced_model(): void
    {
        $auditTool = $this->budgetedAuditTool($this->budgetGuard(null, ['mystery-model']));

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertSame($this->projectPath, $report['project']);
    }

    /**
     * The `audit:run` command answers a run whose scan found no file with exit
     * `1`: nothing was examined, so there is no verdict to return. The tool
     * refuses it the same way instead of answering grade A.
     */
    public function test_it_refuses_a_verdict_on_a_project_where_the_scan_found_no_file(): void
    {
        $auditTool = $this->auditTool(pipeline: self::createStub(PipelineInterface::class));

        try {
            $auditTool->audit($this->projectPath);
            self::fail('A run that found no file must not return a report.');
        } catch (ToolCallException $toolCallException) {
            self::assertStringContainsString('has no verdict: the scan found no file to audit', $toolCallException->getMessage());
            self::assertInstanceOf(AuditWithoutVerdictException::class, $toolCallException->getPrevious());
        }
    }

    public function test_it_refuses_a_verdict_when_no_file_could_be_analyzed(): void
    {
        $auditTool = $this->auditTool(pipeline: new SingleFileAuditPipeline('errored'));

        try {
            $auditTool->audit($this->projectPath);
            self::fail('A run that analyzed no file must not return a report.');
        } catch (ToolCallException $toolCallException) {
            self::assertSame(
                \sprintf('The audit of "%s" has no verdict: none of its 1 file(s) could be analyzed (a scan or LLM call failed, or the run stopped before reaching them). The server log names the cause.', $this->projectPath),
                $toolCallException->getMessage(),
            );
        }
    }

    /**
     * @throws ToolCallException
     */
    public function test_it_reports_a_run_that_analyzed_some_of_its_files_as_incomplete(): void
    {
        $report = json_decode($this->auditTool(pipeline: new PartlyFailedPipeline())->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertFalse($report['complete']);
    }

    /**
     * @throws ToolCallException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_returns_the_finding_of_a_run_that_analyzed_no_file_as_an_incomplete_report(): void
    {
        $auditTool = $this->auditTool(pipeline: new SingleFileAuditPipeline('errored', $this->validatedFinding(VulnerabilityType::SQL_INJECTION)));

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertFalse($report['complete']);
        self::assertSame(1, $report['total_vulnerabilities']);
    }

    /**
     * @throws ToolCallException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_leaves_out_the_finding_types_the_configuration_mutes(): void
    {
        $auditTool = $this->auditTool(
            pipeline: new SingleFileAuditPipeline('analyzed', $this->validatedFinding(VulnerabilityType::SQL_INJECTION)),
            findingTypeFilter: new FindingTypeFilter([], [VulnerabilityType::SQL_INJECTION->value]),
        );

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertSame(0, $report['total_vulnerabilities']);
    }

    /**
     * @throws ToolCallException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_suppresses_the_findings_the_configured_baseline_accepts(): void
    {
        $vulnerability = $this->validatedFinding(VulnerabilityType::SQL_INJECTION);
        $auditTool = $this->auditTool(
            pipeline: new SingleFileAuditPipeline('analyzed', $vulnerability, $this->validatedFinding(VulnerabilityType::SSRF)),
            configuredBaseline: $this->baselineAccepting($vulnerability, 'The id is cast to int upstream.'),
        );

        $report = json_decode($auditTool->audit($this->projectPath), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertSame(['ssrf'], array_column(\is_array($report['vulnerabilities']) ? $report['vulnerabilities'] : [], 'type'));
    }

    /**
     * @throws ToolCallException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_findings_the_configured_baseline_accepts_skip_the_reviewer(): void
    {
        $vulnerability = $this->validatedFinding(VulnerabilityType::SQL_INJECTION);
        $singleFileAuditPipeline = new SingleFileAuditPipeline('analyzed');

        $this->auditTool(pipeline: $singleFileAuditPipeline, configuredBaseline: $this->baselineAccepting($vulnerability, 'The id is cast to int upstream.'))->audit($this->projectPath);

        self::assertSame([$vulnerability->fingerprint()], $singleFileAuditPipeline->acceptedFingerprints);
    }

    /**
     * @throws ToolCallException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_hands_the_configured_baseline_reasons_to_the_reviewer(): void
    {
        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $vulnerability = $this->validatedFinding(VulnerabilityType::SQL_INJECTION);

        $auditTool = new AuditTool(
            new RunAuditUseCase(new SingleFileAuditPipeline(), new NullLogger()),
            new JsonReportRenderer(),
            $this->auditedProjectPathHolder(),
            new BaselineProcessor(new Baseline(), $this->baselineAccepting($vulnerability, 'The id is cast to int upstream.')),
            new FindingTypeFilter(),
            $reviewerFeedbackHolder,
            $this->budgetGuard(),
        );

        $auditTool->audit($this->projectPath);

        self::assertSame(
            ['The id is cast to int upstream.'],
            array_map(static fn (AcceptedFindingFeedback $acceptedFindingFeedback): string => $acceptedFindingFeedback->reason, $reviewerFeedbackHolder->feedback()->entries),
        );
    }

    private function auditTool(
        ?PipelineInterface $pipeline = null,
        ?ReportRendererInterface $reportRenderer = null,
        ?AuditedProjectPathHolder $auditedProjectPathHolder = null,
        ?FindingTypeFilter $findingTypeFilter = null,
        ?string $configuredBaseline = null,
    ): AuditTool {
        return new AuditTool(
            new RunAuditUseCase($pipeline ?? new SingleFileAuditPipeline(), new NullLogger()),
            $reportRenderer ?? new JsonReportRenderer(),
            $auditedProjectPathHolder ?? $this->auditedProjectPathHolder(),
            new BaselineProcessor(new Baseline(), $configuredBaseline),
            $findingTypeFilter ?? new FindingTypeFilter(),
            new ReviewerFeedbackHolder(),
            $this->budgetGuard(),
        );
    }

    private function budgetedAuditTool(UnpricedModelBudgetGuardInterface $unpricedModelBudgetGuard, ?PipelineInterface $pipeline = null): AuditTool
    {
        return new AuditTool(
            new RunAuditUseCase($pipeline ?? new SingleFileAuditPipeline(), new NullLogger()),
            new JsonReportRenderer(),
            $this->auditedProjectPathHolder(),
            new BaselineProcessor(new Baseline()),
            new FindingTypeFilter(),
            new ReviewerFeedbackHolder(),
            $unpricedModelBudgetGuard,
        );
    }

    /** @param list<string> $models */
    private function budgetGuard(?float $maxCostUsd = null, array $models = []): UnpricedModelBudgetGuard
    {
        $pricing = self::createStub(PricingProviderInterface::class);
        $pricing->method('hasModel')->willReturnCallback(static fn (string $model): bool => 'priced-model' === $model);

        return new UnpricedModelBudgetGuard($pricing, $models, $maxCostUsd);
    }

    private function auditedProjectPathHolder(): AuditedProjectPathHolder
    {
        return new AuditedProjectPathHolder('/default/project/dir');
    }

    private function baselineAccepting(Vulnerability $vulnerability, string $reason): string
    {
        $baselineFile = $this->projectPath.'/.security-baseline.json';
        (new Filesystem())->dumpFile($baselineFile, json_encode([[
            'fingerprint' => $vulnerability->fingerprint(),
            'type' => $vulnerability->type()->value,
            'file' => $vulnerability->filePath(),
            'title' => $vulnerability->title(),
            'reason' => $reason,
        ]], \JSON_THROW_ON_ERROR));

        return $baselineFile;
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function validatedFinding(VulnerabilityType $vulnerabilityType): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, VulnerabilitySeverity::HIGH, \sprintf('A %s finding', $vulnerabilityType->value), 0.9),
            new CodeLocation(SingleFileAuditPipeline::FILE, 3, 5),
            new VulnerabilityNarrative('Description', 'Vector', 'Proof', 'Fix'),
            '$code',
        )->withReviewerValidation(true);
    }
}
