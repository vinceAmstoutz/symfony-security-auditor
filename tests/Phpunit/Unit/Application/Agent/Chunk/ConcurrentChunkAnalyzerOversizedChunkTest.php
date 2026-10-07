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

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ConcurrentChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMFixedPromptTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ConcurrentChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class ConcurrentChunkAnalyzerOversizedChunkTest extends TestCase
{
    /**
     * @return array<string, int> coverage status => count, sorted by status
     */
    private function statusCounts(RecordingCoverageRecorder $recordingCoverageRecorder): array
    {
        return ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder);
    }

    private function makeAnalyzer(ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient, int $maxConcurrent, ?AttackerCacheInterface $attackerCache = null, ?LoggerInterface $logger = null): ConcurrentChunkAnalyzer
    {
        return ConcurrentChunkAnalyzerHarness::analyzer($toolBatchCapableLLMClient, $maxConcurrent, $attackerCache, $logger);
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

    /**
     * A client whose model fits exactly one file per request: a request
     * carrying several files is answered as too large, and a one-file request
     * records a finding named after that file. `$expectedCalls` pins how many
     * requests the analyzer needs to get every file answered.
     */
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
