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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\UseCase;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\StaticPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class RunAuditUseCaseIntegrationTest extends TestCase
{
    private string $tmpDir;

    public function test_execute_report_contains_correct_project_path(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Service.php', '<?php class Service {}');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertSame($this->tmpDir, $auditReport->projectPath());
    }

    public function test_execute_report_files_scanned_matches_real_file_count(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        mkdir($this->tmpDir.'/src/Entity', 0o777, true);

        file_put_contents($this->tmpDir.'/src/Controller/UserController.php', '<?php');
        file_put_contents($this->tmpDir.'/src/Entity/User.php', '<?php');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertSame(2, $auditReport->filesScanned());
    }

    public function test_execute_returns_safe_report_when_no_vulnerabilities_found(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Service.php', '<?php class Service {}');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertSame('SAFE', $auditReport->riskLevel());
        self::assertSame(0, $auditReport->totalVulnerabilities());
    }

    public function test_execute_report_contains_vulnerability_found_by_stub_llm(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/AdminController.php',
            '<?php class AdminController { public function dashboard() {} }',
        );

        $vulnJson = $this->makeVulnerabilityJson('src/Controller/AdminController.php');
        $reviewJson = (string) json_encode(['accepted' => true, 'adjusted_severity' => null, 'reviewer_notes' => 'Confirmed']);

        $auditReport = $this->makeUseCase($vulnJson, $reviewJson)->execute($this->tmpDir);

        self::assertSame(1, $auditReport->totalVulnerabilities());
        self::assertSame('Missing access control on admin route', $auditReport->vulnerabilities()[0]->title());
    }

    public function test_execute_attaches_token_and_cost_telemetry_to_report(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php class App {}');

        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(120, 30);

        $auditReport = $this->makeUseCaseWithTelemetry('[]', '{}', $tokenUsageRecorder)->execute($this->tmpDir);

        self::assertSame(120, $auditReport->cost()->inputTokens());
        self::assertSame(30, $auditReport->cost()->outputTokens());
        self::assertSame('gpt-4o', $auditReport->cost()->primaryModel());
        self::assertGreaterThan(0.0, $auditReport->cost()->estimatedCostUsd());
    }

    public function test_execute_includes_cache_tokens_in_the_reported_cost(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php class App {}');

        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(0, 0, 0, 1_000_000);

        $auditReport = $this->makeUseCaseWithTelemetry('[]', '{}', $tokenUsageRecorder)->execute($this->tmpDir);

        self::assertSame(0, $auditReport->cost()->inputTokens());
        self::assertSame(0, $auditReport->cost()->outputTokens());
        self::assertGreaterThan(0.0, $auditReport->cost()->estimatedCostUsd());
    }

    public function test_execute_wraps_budget_exception_with_partial_report(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php class App {}');

        $abortingAttacker = self::createStub(LLMClientInterface::class);
        $abortingAttacker->method('complete')->willThrowException(BudgetExceededException::forTokens(5_000, 100));
        $abortingAttacker->method('completeWithTools')->willThrowException(BudgetExceededException::forTokens(5_000, 100));
        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(LLMResponse::of('{}', 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $runAuditUseCase = $this->makeUseCaseWithLLM($abortingAttacker, $reviewerLLM);

        try {
            $runAuditUseCase->execute($this->tmpDir);
            self::fail('Expected AuditAbortedByBudgetException');
        } catch (AuditAbortedByBudgetException $auditAbortedByBudgetException) {
            self::assertSame('Audit aborted: token budget exceeded (5000 / 100 tokens)', $auditAbortedByBudgetException->getMessage());
            self::assertSame(1, $auditAbortedByBudgetException->partialReport()->filesScanned());
            self::assertSame(0, $auditAbortedByBudgetException->partialReport()->totalVulnerabilities());
        }
    }

    public function test_execute_attaches_zero_cost_when_recorder_set_but_calculator_omitted(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');

        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(LLMResponse::of('[]', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(0, 0)));
        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(LLMResponse::of('{}', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator())),
                new AttackerScanCollaborators(new NullAttackerCache()),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLLM,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                ),
                new ReviewerModeConfiguration(),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
        );
        $auditPipeline = new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
        );

        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(42, 7);

        $runAuditUseCase = new RunAuditUseCase(
            $auditPipeline,
            new NullLogger(),
            $tokenUsageRecorder,
            null,
            'gpt-4o',
        );

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(42, $auditReport->cost()->inputTokens());
        self::assertSame(7, $auditReport->cost()->outputTokens());
        self::assertSame(0.0, $auditReport->cost()->estimatedCostUsd());
    }

    public function test_execute_propagates_reviewer_budget_exception_as_audit_aborted(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/AdminController.php',
            '<?php class AdminController { public function dashboard() {} }',
        );

        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(LLMResponse::of(
            $this->makeVulnerabilityJson('src/Controller/AdminController.php'),
            'stub',
            'end_turn',
            TokenUsageSnapshot::of(0, 0),
        ));
        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willThrowException(BudgetExceededException::forCost(2.0, 1.0));

        $runAuditUseCase = $this->makeUseCaseWithLLM($attackerLLM, $reviewerLLM);

        $this->expectException(AuditAbortedByBudgetException::class);
        $runAuditUseCase->execute($this->tmpDir);
    }

    public function test_execute_propagates_reviewer_batch_budget_exception(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/AdminController.php',
            '<?php class AdminController { public function dashboard() {} }',
        );

        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(LLMResponse::of(
            $this->makeVulnerabilityJson('src/Controller/AdminController.php'),
            'stub',
            'end_turn',
            TokenUsageSnapshot::of(0, 0),
        ));
        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willThrowException(BudgetExceededException::forCost(2.0, 1.0));

        // batchSize > 1 routes through reviewBatch instead of reviewSingle.
        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator())),
                new AttackerScanCollaborators(new NullAttackerCache()),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLLM,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                ),
                new ReviewerModeConfiguration(batchSize: 5),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
        );
        $auditPipeline = new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
        );

        $runAuditUseCase = new RunAuditUseCase($auditPipeline, new NullLogger());

        $this->expectException(AuditAbortedByBudgetException::class);
        $runAuditUseCase->execute($this->tmpDir);
    }

    public function test_execute_warns_logger_when_budget_aborts_the_audit(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');

        $abortingAttacker = self::createStub(LLMClientInterface::class);
        $abortingAttacker->method('complete')->willThrowException(BudgetExceededException::forCost(2.5, 1.0));
        $abortingAttacker->method('completeWithTools')->willThrowException(BudgetExceededException::forCost(2.5, 1.0));
        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(LLMResponse::of('{}', 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info');
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $runAuditUseCase = $this->makeUseCaseWithLLMAndLogger($abortingAttacker, $reviewerLLM, $logger);

        $budgetAborted = false;
        try {
            $runAuditUseCase->execute($this->tmpDir);
        } catch (AuditAbortedByBudgetException) {
            $budgetAborted = true;
        }

        self::assertTrue($budgetAborted, 'Expected AuditAbortedByBudgetException');

        $abortLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Audit aborted by budget cap' === $entry[0],
        ));
        self::assertCount(1, $abortLogs);
        self::assertArrayHasKey('audit_id', $abortLogs[0][1]);
        self::assertArrayHasKey('error', $abortLogs[0][1]);
    }

    public function test_execute_report_audit_id_is_non_empty(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertNotEmpty($auditReport->auditId());
        self::assertStringStartsWith('AUDIT-', $auditReport->auditId());
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/usecase_int_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursive($this->tmpDir);
    }

    private function makeUseCase(string $attackerResponse, string $reviewerResponse): RunAuditUseCase
    {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of($attackerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of($reviewerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        return $this->makeUseCaseWithLLM($attackerLLM, $reviewerLLM);
    }

    private function makeUseCaseWithLLM(LLMClientInterface $attackerLLM, LLMClientInterface $reviewerLLM): RunAuditUseCase
    {
        return $this->makeUseCaseWithLLMAndLogger($attackerLLM, $reviewerLLM, new NullLogger());
    }

    private function makeUseCaseWithLLMAndLogger(
        LLMClientInterface $attackerLLM,
        LLMClientInterface $reviewerLLM,
        LoggerInterface $logger,
    ): RunAuditUseCase {
        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator())),
                new AttackerScanCollaborators(new NullAttackerCache()),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLLM,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                ),
                new ReviewerModeConfiguration(),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
        );

        $auditPipeline = new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
        );

        return new RunAuditUseCase($auditPipeline, $logger);
    }

    private function makeUseCaseWithTelemetry(
        string $attackerResponse,
        string $reviewerResponse,
        TokenUsageRecorder $tokenUsageRecorder,
    ): RunAuditUseCase {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of($attackerResponse, 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of($reviewerResponse, 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator())),
                new AttackerScanCollaborators(new NullAttackerCache()),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLLM,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                ),
                new ReviewerModeConfiguration(),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
        );

        $auditPipeline = new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
        );

        return new RunAuditUseCase(
            $auditPipeline,
            new NullLogger(),
            $tokenUsageRecorder,
            new CostCalculator(new StaticPricingProvider(new NullLogger())),
            'gpt-4o',
        );
    }

    private function makeVulnerabilityJson(string $filePath): string
    {
        return (string) json_encode([[
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'Missing access control on admin route',
            'description' => 'No security check on the admin route',
            'file_path' => $filePath,
            'line_start' => 10,
            'line_end' => 20,
            'vulnerable_code' => 'public function dashboard()',
            'attack_vector' => 'Direct URL access',
            'proof' => 'GET /admin/dashboard',
            'remediation' => 'Add #[IsGranted("ROLE_ADMIN")]',
            'confidence' => 0.9,
        ]]);
    }

    private function rmdirRecursive(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) as $item) {
            if ('.' === $item) {
                continue;
            }

            if ('..' === $item) {
                continue;
            }

            $path = $dir.'/'.$item;
            is_dir($path) ? $this->rmdirRecursive($path) : unlink($path);
        }

        rmdir($dir);
    }
}
