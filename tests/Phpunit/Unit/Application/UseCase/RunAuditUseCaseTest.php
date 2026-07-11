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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
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
        $tokenUsageRecorder = new TokenUsageRecorder();
        $recordingCostStage = new class($budgetTracker, $tokenUsageRecorder) implements StageInterface {
            public function __construct(
                private readonly BudgetTracker $budgetTracker,
                private readonly TokenUsageRecorder $tokenUsageRecorder,
            ) {}

            #[Override]
            public function name(): string
            {
                return 'recording-cost';
            }

            /**
             * @throws InvalidTokenUsageException
             * @throws NegativeTokenCountException
             */
            #[Override]
            public function process(AuditContext $auditContext): void
            {
                $this->budgetTracker->recordCall(LLMResponse::of('', 'attacker-model', 'end_turn', TokenUsageSnapshot::of(1_000_000, 100_000)));
                $this->budgetTracker->recordCall(LLMResponse::of('', 'reviewer-model', 'end_turn', TokenUsageSnapshot::of(500_000, 50_000)));

                $this->tokenUsageRecorder->record(1_500_000, 150_000);
            }
        };

        $runAuditUseCase = new RunAuditUseCase(
            $this->makePipeline($recordingCostStage),
            new NullLogger(),
            $tokenUsageRecorder,
            $costCalculator,
            'attacker-model',
            $budgetTracker,
        );

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(9.25, $auditReport->cost()->estimatedCostUsd());
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    public function test_it_resets_token_usage_between_separate_execute_calls_on_the_same_instance(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $recordingCostStage = new class($tokenUsageRecorder) implements StageInterface {
            public function __construct(private readonly TokenUsageRecorder $tokenUsageRecorder) {}

            #[Override]
            public function name(): string
            {
                return 'recording-cost';
            }

            /**
             * @throws NegativeTokenCountException
             */
            #[Override]
            public function process(AuditContext $auditContext): void
            {
                $this->tokenUsageRecorder->record(1000, 500);
            }
        };

        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($recordingCostStage), new NullLogger(), $tokenUsageRecorder);

        $runAuditUseCase->execute($this->tmpDir);

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(1000, $auditReport->cost()->inputTokens());
        self::assertSame(500, $auditReport->cost()->outputTokens());
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    public function test_it_resets_the_budget_tracker_between_separate_execute_calls_on_the_same_instance(): void
    {
        $pricingProvider = new class implements PricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 10.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
        $costCalculator = new CostCalculator($pricingProvider);
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), $costCalculator);
        $tokenUsageRecorder = new TokenUsageRecorder();

        $recordingCostStage = new class($budgetTracker, $tokenUsageRecorder) implements StageInterface {
            public function __construct(
                private readonly BudgetTracker $budgetTracker,
                private readonly TokenUsageRecorder $tokenUsageRecorder,
            ) {}

            #[Override]
            public function name(): string
            {
                return 'recording-cost';
            }

            /**
             * @throws InvalidTokenUsageException
             * @throws NegativeTokenCountException
             */
            #[Override]
            public function process(AuditContext $auditContext): void
            {
                $this->budgetTracker->recordCall(LLMResponse::of('', 'attacker-model', 'end_turn', TokenUsageSnapshot::of(1_000_000, 0)));
                $this->tokenUsageRecorder->record(1_000_000, 0);
            }
        };

        $runAuditUseCase = new RunAuditUseCase(
            $this->makePipeline($recordingCostStage),
            new NullLogger(),
            $tokenUsageRecorder,
            $costCalculator,
            'attacker-model',
            $budgetTracker,
        );

        $runAuditUseCase->execute($this->tmpDir);

        $auditReport = $runAuditUseCase->execute($this->tmpDir);

        self::assertSame(10.0, $auditReport->cost()->estimatedCostUsd());
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function test_it_logs_provider_failure_abort_with_exact_context(): void
    {
        $throwingStage = new class implements StageInterface {
            #[Override]
            public function name(): string
            {
                return 'throwing';
            }

            /**
             * @throws LLMProviderException
             */
            #[Override]
            public function process(AuditContext $auditContext): void
            {
                throw new LLMProviderException('provider exploded');
            }
        };

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $runAuditUseCase = new RunAuditUseCase($this->makePipeline($throwingStage), $logger);

        $thrown = null;

        try {
            $runAuditUseCase->execute($this->tmpDir);
        } catch (AuditAbortedByProviderException $auditAbortedByProviderException) {
            $thrown = $auditAbortedByProviderException;
        }

        self::assertInstanceOf(AuditAbortedByProviderException::class, $thrown);

        $providerFailureWarnings = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Audit aborted by LLM provider failure' === $entry[0],
        ));
        self::assertCount(1, $providerFailureWarnings);
        self::assertSame(
            ['audit_id' => $thrown->partialReport()->auditId(), 'error' => 'provider exploded'],
            $providerFailureWarnings[0][1],
        );
    }

    private function makePipeline(?StageInterface $stage = null): AuditPipeline
    {
        return new AuditPipeline($stage instanceof StageInterface ? [$stage] : [], new NullLogger(), new NullProgressReporter());
    }
}
