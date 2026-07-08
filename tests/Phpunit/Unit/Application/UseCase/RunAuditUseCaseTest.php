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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\RecordingStage;

final class RunAuditUseCaseTest extends TestCase
{
    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/usecase_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_runs_pipeline_against_the_audit_context(): void
    {
        $recordingStage = new RecordingStage();
        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingStage), new NullLogger());

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertCount(1, $recordingStage->processedAuditIds);
        self::assertSame($auditReport->auditId(), $recordingStage->processedAuditIds[0]);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_threads_accepted_fingerprints_into_the_audit_context(): void
    {
        $recordingStage = new RecordingStage();
        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingStage), new NullLogger());

        $runAuditUseCase->execute($this->tmpDir, acceptedFingerprints: ['SSA-AAA', 'SSA-BBB']);

        self::assertSame([['SSA-AAA', 'SSA-BBB']], $recordingStage->observedAcceptedFingerprints);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_logs_starting_audit_with_project_path(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $runAuditUseCase = new RunAuditUseCase($this->makePipeline(), $logger);
        $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(
            ['Starting audit', ['project' => $this->tmpDir, 'scan_paths' => [], 'cache_bypassed' => false, 'diff_since_ref' => null, 'accepted_fingerprints' => 0]],
            $infoLogs[0],
        );
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_marks_the_audit_context_as_cache_bypassed_when_requested(): void
    {
        $recordingStage = new RecordingStage();
        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingStage), new NullLogger());

        $runAuditUseCase->execute($this->tmpDir, [], true);

        self::assertSame([true], $recordingStage->observedCacheBypassed);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_passes_scan_paths_to_the_pipeline_via_audit_context(): void
    {
        $recordingStage = new RecordingStage();
        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingStage), new NullLogger());

        $runAuditUseCase->execute($this->tmpDir, ['apps/api/src']);

        self::assertSame([['apps/api/src']], $recordingStage->observedScanPaths);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_logs_audit_complete_with_exact_context(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $runAuditUseCase = new RunAuditUseCase($this->makePipeline(), $logger);
        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        $completeLog = array_values(array_filter($infoLogs, static fn (array $e): bool => 'Audit complete' === $e[0]))[0];
        self::assertSame($auditReport->auditId(), $completeLog[1]['audit_id']);
        self::assertSame($auditReport->riskLevel(), $completeLog[1]['risk_level']);
        self::assertSame(0, $completeLog[1]['vulnerabilities']);
        self::assertIsFloat($completeLog[1]['duration']);
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    public function test_it_prices_the_reported_cost_per_model_via_the_budget_tracker_instead_of_a_single_blended_rate(): void
    {
        $pricingProvider = new class implements PricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 'attacker-model' === $model ? 5.0 : 2.5;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 'attacker-model' === $model ? 25.0 : 10.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
        $costCalculator = new CostCalculator($pricingProvider);

        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), $costCalculator);
        $budgetTracker->recordCall(LLMResponse::of('', 'attacker-model', 'end_turn', TokenUsageSnapshot::of(1_000_000, 100_000)));
        $budgetTracker->recordCall(LLMResponse::of('', 'reviewer-model', 'end_turn', TokenUsageSnapshot::of(500_000, 50_000)));

        $tokenUsageRecorder = new TokenUsageRecorder();
        $tokenUsageRecorder->record(1_500_000, 150_000);

        $runAuditUseCase = new RunAuditUseCase(
            $this->makePipeline(),
            new NullLogger(),
            $tokenUsageRecorder,
            $costCalculator,
            'attacker-model',
            $budgetTracker,
        );

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(9.25, $auditReport->cost()->estimatedCostUsd());
    }

    private function makePipeline(?StageInterface $stage = null): AuditPipeline
    {
        return new AuditPipeline($stage instanceof StageInterface ? [$stage] : [], new NullLogger(), new NullProgressReporter());
    }
}
