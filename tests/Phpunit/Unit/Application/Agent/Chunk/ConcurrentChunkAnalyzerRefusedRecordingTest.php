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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ConcurrentChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\DescriptionRequiringToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ConcurrentChunkAnalyzerRefusedRecordingTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_only_the_window_entry_that_ended_after_a_refused_recording_call_is_recorded_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->execute('record_vulnerability', ConcurrentChunkAnalyzerHarness::recordedFinding('recorded'));
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->execute('record_vulnerability', self::withoutDescription('refused'));
            ConcurrentChunkAnalyzerHarness::registryOf($requests[1])->execute('record_vulnerability', ConcurrentChunkAnalyzerHarness::recordedFinding('complete'));

            return [
                LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
            ];
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => $chunk[0] instanceof ProjectFile && 'src/B.php' === $chunk[0]->relativePath()),
            self::anything(),
        );
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker finding was refused by the recording tool and never recorded again; the chunk is recorded as errored and left out of the cache',
            ['files' => ['src/A.php'], 'findings_kept' => 1, 'refused_calls' => 1],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzerRecordingThrough($llmClient, 4, new DescriptionRequiringToolFactory(), $attackerCache, $logger)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['recorded', 'complete'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['analyzed' => 1, 'errored' => 1], ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'reason' => 'a finding the record tool refused was never recorded again']], $recordingCoverageRecorder->failureReasons);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_every_refused_recording_call_the_model_never_repeats_is_counted(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            $toolRegistry = ConcurrentChunkAnalyzerHarness::registryOf($requests[0]);
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused'));
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused too'));
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused and repeated'));
            $toolRegistry->execute('record_vulnerability', ConcurrentChunkAnalyzerHarness::recordedFinding('refused and repeated'));

            return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
        });
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            self::anything(),
            ['files' => ['src/A.php'], 'findings_kept' => 1, 'refused_calls' => 2],
        );

        ConcurrentChunkAnalyzerHarness::analyzerRecordingThrough($llmClient, 4, new DescriptionRequiringToolFactory(), null, $logger)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), new RiskMarkerIndex([]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_refused_recording_call_the_model_repeats_in_full_leaves_the_window_entry_analyzed_and_cached(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->execute('record_vulnerability', self::withoutDescription('repeated'));
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->execute('record_vulnerability', ConcurrentChunkAnalyzerHarness::recordedFinding('repeated'));

            return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        ConcurrentChunkAnalyzerHarness::analyzerRecordingThrough($llmClient, 4, new DescriptionRequiringToolFactory(), $attackerCache)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['analyzed' => 1], ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder));
        self::assertSame([], $recordingCoverageRecorder->failureReasons);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_window_entry_stopped_at_the_tool_cap_after_a_refused_call_keeps_the_cap_as_its_reason(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->execute('record_vulnerability', self::withoutDescription('refused'));

            return [LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1))];
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        ConcurrentChunkAnalyzerHarness::analyzerRecordingThrough($llmClient, 4, new DescriptionRequiringToolFactory())
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'reason' => 'tool-call limit reached (audit.max_tool_iterations)']], $recordingCoverageRecorder->failureReasons);
    }

    /**
     * @return array<string, mixed>
     */
    private static function withoutDescription(string $title): array
    {
        $finding = ConcurrentChunkAnalyzerHarness::recordedFinding($title);
        unset($finding['description']);

        return $finding;
    }
}
