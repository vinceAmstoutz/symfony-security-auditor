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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ConcurrentChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ConcurrentChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture\RecordingProgressReporter;

final class ConcurrentChunkAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_it_records_a_cached_chunks_findings_as_found_vulnerabilities(): void
    {
        $cache = self::createStub(AttackerCacheInterface::class);
        $cache->method('get')->willReturn([self::recordedFinding('cached-finding')]);

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);

        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 4, $cache);

        $concurrentChunkAnalyzer->analyze([[$this->makeFile('src/A.php')]], $this->request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['cached-finding'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $recordingCoverageRecorder->found));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_max_concurrent_of_one_dispatches_each_pending_chunk_in_its_own_window(): void
    {
        $requestCounts = [];
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$requestCounts): array {
                $requestCounts[] = \count($requests);
                foreach ($requests as $request) {
                    self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('finding'));
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 1);

        $concurrentChunkAnalyzer->analyze(
            [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            new RiskMarkerIndex([]),
        );

        self::assertSame([1, 1], $requestCounts);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_generic_failure_in_a_later_window_preserves_every_earlier_windows_result(): void
    {
        $callCount = 0;
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$callCount): array {
                ++$callCount;
                if (2 === $callCount) {
                    throw new RuntimeException('second window tore');
                }

                foreach ($requests as $request) {
                    self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('first-window'));
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 2);

        [$vulnerabilities] = $concurrentChunkAnalyzer->analyze(
            [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')], [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            new RiskMarkerIndex([]),
        );

        self::assertCount(2, $vulnerabilities);
    }

    /**
     * A generic batch failure must be isolated to its own window: the windows
     * after it still have to be dispatched, exactly as the sequential analyzer
     * keeps analysing chunks after one errors. Otherwise a single odd runtime
     * error silently drops every later file from the audit — a false-negative
     * SAFE for a security tool.
     *
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_generic_failure_in_a_middle_window_still_dispatches_the_windows_after_it(): void
    {
        $callCount = 0;
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(3))
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$callCount): array {
                ++$callCount;
                if (2 === $callCount) {
                    throw new RuntimeException('middle window tore');
                }

                foreach ($requests as $request) {
                    self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('window-'.$callCount));
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 2);

        [$vulnerabilities] = $concurrentChunkAnalyzer->analyze(
            [
                [$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')],
                [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')],
                [$this->makeFile('src/E.php')], [$this->makeFile('src/F.php')],
            ],
            $this->request(),
            new RecordingCoverageRecorder(),
            new RiskMarkerIndex([]),
        );

        self::assertCount(4, $vulnerabilities);
    }

    /**
     * A budget abort is fatal: the window that hit the cap and every window
     * after it are recorded `aborted` (windows already finalized keep their
     * `analyzed` status) and the exception propagates.
     *
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_budget_abort_in_a_later_window_records_the_remaining_windows_as_aborted(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($this->clientFailingOnSecondWindowWith(BudgetExceededException::forTokens(150, 100)), 2)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')], [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (BudgetExceededException $budgetExceededException) {
            $caught = $budgetExceededException;
        }

        self::assertInstanceOf(BudgetExceededException::class, $caught);
        self::assertSame(['aborted' => 2, 'analyzed' => 2], $this->statusCounts($recordingCoverageRecorder));
    }

    /**
     * A provider failure is fatal in the same way, recorded as `errored`.
     *
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     */
    public function test_a_provider_abort_in_a_later_window_records_the_remaining_windows_as_errored(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($this->clientFailingOnSecondWindowWith(new LLMProviderException('provider down')), 2)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')], [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (LLMProviderException $llmProviderException) {
            $caught = $llmProviderException;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
        self::assertSame(['analyzed' => 2, 'errored' => 2], $this->statusCounts($recordingCoverageRecorder));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finalize_failure_logs_a_warning_carrying_the_underlying_error(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );

        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests): array {
                self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('finding'));

                return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
            });

        $throwingCoverageRecorder = new class implements CoverageRecorderInterface {
            #[Override]
            public function recordCoverage(string $stage, string $filePath, string $status): void
            {
                if ('analyzed' === $status) {
                    throw new RuntimeException('coverage sink unavailable');
                }
            }

            #[Override]
            public function recordReviewedFinding(Vulnerability $vulnerability): void {}

            #[Override]
            public function drainReviewedFindings(): array
            {
                return [];
            }

            #[Override]
            public function recordFoundVulnerability(Vulnerability $vulnerability): void {}

            #[Override]
            public function drainFoundVulnerabilities(): array
            {
                return [];
            }
        };

        $concurrentChunkAnalyzer = $this->makeAnalyzer($llmClient, 4, null, $logger);

        $concurrentChunkAnalyzer->analyze([[$this->makeFile('src/A.php')]], $this->request(), $throwingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertContains(
            ['Finalizing an attacker chunk result failed; the chunk is recorded as errored and its siblings in the same window are preserved.', ['error' => 'coverage sink unavailable']],
            $warnings,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_window_entry_stopped_at_the_tool_cap_reports_the_cap_as_the_reason_its_chunk_failed(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturn([
            LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
            LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1)),
        ]);
        $recordingProgressReporter = new RecordingProgressReporter();

        $this->makeAnalyzer($llmClient, 4, progressReporter: $recordingProgressReporter)->analyze([[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]], $this->request(), new RecordingCoverageRecorder(), new RiskMarkerIndex([]));

        $completed = $recordingProgressReporter->eventsNamed('attacker.chunk.completed');
        self::assertSame(['analyzed', 'errored'], array_column($completed, 'status'));
        self::assertArrayNotHasKey('reason', $completed[0]);
        self::assertSame('tool-call limit reached (audit.max_tool_iterations)', $completed[1]['reason']);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_batch_that_failed_reports_its_error_as_the_reason_every_chunk_of_its_window_failed(): void
    {
        $recordingProgressReporter = new RecordingProgressReporter();

        $this->makeAnalyzer($this->clientFailingOnSecondWindowWith(new RuntimeException("second window\ntore")), 2, progressReporter: $recordingProgressReporter)->analyze(
            [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')], [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            new RiskMarkerIndex([]),
        );

        $completed = $recordingProgressReporter->eventsNamed('attacker.chunk.completed');
        self::assertSame(['analyzed', 'analyzed', 'errored', 'errored'], array_column($completed, 'status'));
        self::assertSame('second window tore', $completed[2]['reason']);
        self::assertSame('second window tore', $completed[3]['reason']);
    }

    /**
     * A client whose first window succeeds (recording a finding per chunk) and
     * whose second window throws `$failure`, so a later-window abort is
     * reached with an earlier window already finalized.
     */
    private function clientFailingOnSecondWindowWith(Throwable $throwable): ToolBatchCapableLLMClientInterface
    {
        $callCount = 0;
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient
            ->expects(self::exactly(2))
            ->method('completeBatchWithTools')
            ->willReturnCallback(static function (array $requests) use (&$callCount, $throwable): array {
                if (2 === ++$callCount) {
                    throw $throwable;
                }

                foreach ($requests as $request) {
                    self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('first-window'));
                }

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            });

        return $llmClient;
    }

    /**
     * @return array<string, int> coverage status => count, sorted by status
     */
    private function statusCounts(RecordingCoverageRecorder $recordingCoverageRecorder): array
    {
        return ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder);
    }

    private function makeAnalyzer(ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient, int $maxConcurrent, ?AttackerCacheInterface $attackerCache = null, ?LoggerInterface $logger = null, ?ProgressReporterInterface $progressReporter = null): ConcurrentChunkAnalyzer
    {
        return ConcurrentChunkAnalyzerHarness::analyzer($toolBatchCapableLLMClient, $maxConcurrent, $attackerCache, $logger, $progressReporter);
    }

    private function request(): AttackerAnalysisRequest
    {
        return ChunkAnalysisInputs::request();
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ChunkAnalysisInputs::file($path);
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        return ConcurrentChunkAnalyzerHarness::registryOf($request);
    }

    /**
     * @return array<string, mixed>
     */
    private static function recordedFinding(string $title): array
    {
        return ConcurrentChunkAnalyzerHarness::recordedFinding($title);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_window_entry_stopped_at_the_tool_cap_keeps_its_findings_but_is_recorded_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('complete'));
            self::registryOf($requests[1])->execute('record_vulnerability', self::recordedFinding('cut short'));

            return [
                LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1)),
            ];
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => $chunk[0] instanceof ProjectFile && 'src/A.php' === $chunk[0]->relativePath()),
            self::anything(),
        );
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker response was cut short; the chunk is recorded as errored and left out of the cache',
            ['stop_reason' => 'max_tool_iterations', 'files' => ['src/B.php'], 'findings_kept' => 1],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->makeAnalyzer($llmClient, 4, $attackerCache, $logger)->analyze([[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]], $this->request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['complete', 'cut short'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['analyzed' => 1, 'errored' => 1], $this->statusCounts($recordingCoverageRecorder));
        self::assertSame(['complete', 'cut short'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $recordingCoverageRecorder->found));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_budget_abort_records_every_window_never_attempted_as_aborted(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($this->clientFailingOnSecondWindowWith(BudgetExceededException::forTokens(150, 100)), 2)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')], [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')], [$this->makeFile('src/E.php')], [$this->makeFile('src/F.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (BudgetExceededException $budgetExceededException) {
            $caught = $budgetExceededException;
        }

        self::assertInstanceOf(BudgetExceededException::class, $caught);
        self::assertSame(['aborted' => 4, 'analyzed' => 2], $this->statusCounts($recordingCoverageRecorder));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     */
    public function test_a_provider_abort_records_every_window_never_attempted_as_errored(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($this->clientFailingOnSecondWindowWith(new LLMProviderException('provider down')), 2)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')], [$this->makeFile('src/C.php')], [$this->makeFile('src/D.php')], [$this->makeFile('src/E.php')], [$this->makeFile('src/F.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (LLMProviderException $llmProviderException) {
            $caught = $llmProviderException;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
        self::assertSame(['analyzed' => 2, 'errored' => 4], $this->statusCounts($recordingCoverageRecorder));
    }
}
