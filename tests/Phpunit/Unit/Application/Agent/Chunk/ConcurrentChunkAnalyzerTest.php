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
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Validator\Validation;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextKeyDeriver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ConcurrentChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMFixedPromptTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

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
        $counts = array_count_values(array_column($recordingCoverageRecorder->coverage, 'status'));
        ksort($counts);

        return $counts;
    }

    private function makeAnalyzer(ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient, int $maxConcurrent, ?AttackerCacheInterface $attackerCache = null, ?LoggerInterface $logger = null): ConcurrentChunkAnalyzer
    {
        return new ConcurrentChunkAnalyzer(
            $toolBatchCapableLLMClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver()),
            new AttackerChunkCache($attackerCache ?? new NullAttackerCache(), $this->vulnerabilityFactory(), new NullLogger()),
            $this->vulnerabilityFactory(),
            $logger ?? new NullLogger(),
            new NullProgressReporter(),
            3,
            new RecordVulnerabilityToolFactory(),
            $maxConcurrent,
        );
    }

    private function vulnerabilityFactory(): VulnerabilityFactory
    {
        return new VulnerabilityFactory(new NullLogger(), Validation::createValidator());
    }

    private function request(): AttackerAnalysisRequest
    {
        return new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        self::assertIsArray($request);
        $toolRegistry = $request['tools'] ?? null;
        self::assertInstanceOf(ToolRegistry::class, $toolRegistry);

        return $toolRegistry;
    }

    /**
     * @return array<string, mixed>
     */
    private static function recordedFinding(string $title): array
    {
        return [
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => $title,
            'description' => 'desc',
            'file_path' => 'src/A.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.9,
        ];
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
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_chunk_answered_as_too_large_is_split_in_two_while_its_window_siblings_keep_their_answers(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->makeAnalyzer($this->clientFittingOneFilePerRequest(3), 4, null, $warningCollectingLogger)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')], [$this->makeFile('src/C.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from src/A.php', 'from src/B.php', 'from src/C.php'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['analyzed' => 3], $this->statusCounts($recordingCoverageRecorder));
        self::assertSame(
            [['Attacker chunk exceeds the model input limit; it is split in two and each half analyzed on its own', ['files' => ['src/A.php', 'src/B.php'], 'error' => 'prompt is too long']]],
            $warningCollectingLogger->warnings,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_single_file_that_is_most_of_the_refused_prompt_is_recorded_errored_while_its_window_siblings_are_still_analyzed(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            $responses = [];
            foreach ($requests as $request) {
                if (str_contains(self::userPromptOf($request), 'src/A.php')) {
                    $responses[] = self::tooLarge();

                    continue;
                }

                self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('from B'));
                $responses[] = LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            }

            return $responses;
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->makeAnalyzer($llmClient, 2, null, $warningCollectingLogger)->analyze(
            [[$this->makeFileOfSize('src/A.php', 12000)], [$this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed'],
            ],
            $recordingCoverageRecorder->coverage,
        );
        self::assertSame(
            [['Attacker chunk exceeds the model input limit as a single file; it is recorded as errored and left out of the cache', ['files' => ['src/A.php'], 'error' => 'prompt is too long']]],
            $warningCollectingLogger->warnings,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_cached_half_of_a_split_chunk_costs_no_provider_call(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();
        $toolBatchCapableLLMClient = $this->clientFittingOneFilePerRequest(2);
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturnCallback(
            static fn (array $chunk): ?array => 1 === \count($chunk) && $chunk[0] instanceof ProjectFile && 'src/B.php' === $chunk[0]->relativePath() ? [self::recordedFinding('cached B')] : null,
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->makeAnalyzer($toolBatchCapableLLMClient, 4, $attackerCache, $warningCollectingLogger)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from src/A.php', 'cached B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['from src/A.php', 'cached B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $recordingCoverageRecorder->found));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'cached'],
            ],
            $recordingCoverageRecorder->coverage,
        );
        self::assertSame(
            [['Attacker chunk exceeds the model input limit; it is split in two and each half analyzed on its own', ['files' => ['src/A.php', 'src/B.php'], 'error' => 'prompt is too long']]],
            $warningCollectingLogger->warnings,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_budget_abort_in_the_second_half_keeps_the_first_half_analyzed(): void
    {
        $calls = 0;
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function () use (&$calls): array {
            return match (++$calls) {
                1 => [self::tooLarge()],
                2 => [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))],
                default => throw BudgetExceededException::forTokens(150, 100),
            };
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($llmClient, 2)->analyze(
                [[$this->makeFile('src/B.php'), $this->makeFile('src/C.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (BudgetExceededException $budgetExceededException) {
            $caught = $budgetExceededException;
        }

        self::assertInstanceOf(BudgetExceededException::class, $caught);
        self::assertSame(['src/B.php' => 'analyzed', 'src/C.php' => 'aborted'], $this->lastStatusByFile($recordingCoverageRecorder));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     */
    public function test_a_provider_abort_in_the_second_half_keeps_the_first_half_analyzed(): void
    {
        $calls = 0;
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function () use (&$calls): array {
            return match (++$calls) {
                1 => [self::tooLarge()],
                2 => [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))],
                default => throw new LLMProviderException('provider down'),
            };
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($llmClient, 2)->analyze(
                [[$this->makeFile('src/B.php'), $this->makeFile('src/C.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (LLMProviderException $llmProviderException) {
            $caught = $llmProviderException;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
        self::assertSame(['src/B.php' => 'analyzed', 'src/C.php' => 'errored'], $this->lastStatusByFile($recordingCoverageRecorder));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_budget_abort_while_splitting_a_chunk_keeps_the_status_of_its_already_finalized_sibling(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            if (1 === \count($requests)) {
                throw BudgetExceededException::forTokens(150, 100);
            }

            self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('from A'));

            return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)), self::tooLarge()];
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($llmClient, 2)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php'), $this->makeFile('src/C.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (BudgetExceededException $budgetExceededException) {
            $caught = $budgetExceededException;
        }

        self::assertInstanceOf(BudgetExceededException::class, $caught);
        self::assertSame(['src/A.php' => 'analyzed', 'src/B.php' => 'aborted', 'src/C.php' => 'aborted'], $this->lastStatusByFile($recordingCoverageRecorder));
        self::assertSame(['from A'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $recordingCoverageRecorder->found));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_provider_abort_while_splitting_a_chunk_keeps_the_status_of_its_already_finalized_sibling(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            if (1 === \count($requests)) {
                throw new LLMProviderException('platform gone');
            }

            self::registryOf($requests[0])->execute('record_vulnerability', self::recordedFinding('from A'));

            return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)), self::tooLarge()];
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($llmClient, 2)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php'), $this->makeFile('src/C.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (LLMProviderException $llmProviderException) {
            $caught = $llmProviderException;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
        self::assertSame(['src/A.php' => 'analyzed', 'src/B.php' => 'errored', 'src/C.php' => 'errored'], $this->lastStatusByFile($recordingCoverageRecorder));
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

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_small_single_file_answered_as_too_large_stops_the_run_and_records_the_windows_never_reached(): void
    {
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::once())->method('completeBatchWithTools')->willReturn([self::tooLarge()]);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->makeAnalyzer($llmClient, 1)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                new RiskMarkerIndex([]),
            );
        } catch (LLMFixedPromptTooLargeException $llmFixedPromptTooLargeException) {
            $caught = $llmFixedPromptTooLargeException;
        }

        self::assertInstanceOf(LLMFixedPromptTooLargeException::class, $caught);
        self::assertStringContainsString('even with only the 5-byte file "src/A.php" in it (prompt is too long)', $caught->getMessage());
        self::assertSame(['src/A.php' => 'errored', 'src/B.php' => 'errored'], $this->lastStatusByFile($recordingCoverageRecorder));
    }

    /**
     * A client whose model fits exactly one file per request: a request
     * carrying several files is answered as too large, and a one-file request
     * records a finding named after that file. `$expectedCalls` pins how many
     * requests the analyzer needs to get every file answered.
     */
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_the_findings_of_both_halves_are_cached_under_the_whole_chunk_so_the_next_run_does_not_send_it_again(): void
    {
        $stored = [];
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->method('store')->willReturnCallback(static function (array $chunk, array $rawVulnerabilities) use (&$stored): void {
            $stored[] = [self::pathsOf($chunk), array_column($rawVulnerabilities, 'title')];
        });

        [$vulnerabilities] = $this->makeAnalyzer($this->clientFittingOneFilePerRequest(3), 4, $attackerCache)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from src/A.php', 'from src/B.php'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                [['src/A.php'], ['from src/A.php']],
                [['src/B.php'], ['from src/B.php']],
                [['src/A.php', 'src/B.php'], ['from src/A.php', 'from src/B.php']],
            ],
            $stored,
        );
    }

    private function clientFittingOneFilePerRequest(int $expectedCalls): ToolBatchCapableLLMClientInterface
    {
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::exactly($expectedCalls))->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            $responses = [];
            foreach ($requests as $request) {
                $user = self::userPromptOf($request);
                $files = array_values(array_filter(['src/A.php', 'src/B.php', 'src/C.php'], static fn (string $file): bool => str_contains($user, $file)));
                if (1 !== \count($files)) {
                    $responses[] = self::tooLarge();

                    continue;
                }

                self::registryOf($request)->execute('record_vulnerability', self::recordedFinding('from '.$files[0]));
                $responses[] = LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            }

            return $responses;
        });

        return $llmClient;
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function tooLarge(): LLMResponse
    {
        return LLMResponse::of('prompt is too long', 'm', 'request_too_large', TokenUsageSnapshot::of(0, 0));
    }

    /**
     * @return array<string, string> the attacker's last recorded status per file, in first-seen order
     */
    private function lastStatusByFile(RecordingCoverageRecorder $recordingCoverageRecorder): array
    {
        $statuses = [];
        foreach ($recordingCoverageRecorder->coverage as $entry) {
            $statuses[$entry['filePath']] = $entry['status'];
        }

        return $statuses;
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFileOfSize(string $path, int $bytes): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, str_repeat('x', $bytes));
    }

    /**
     * @return list<string>
     */
    private static function pathsOf(mixed $chunk): array
    {
        self::assertIsArray($chunk);
        $paths = [];
        foreach ($chunk as $file) {
            self::assertInstanceOf(ProjectFile::class, $file);
            $paths[] = $file->relativePath();
        }

        return $paths;
    }

    private static function userPromptOf(mixed $request): string
    {
        self::assertIsArray($request);
        $user = $request['user'] ?? null;
        self::assertIsString($user);

        return $user;
    }
}
