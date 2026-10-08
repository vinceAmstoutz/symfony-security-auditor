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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\SequentialChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\DescriptionRequiringToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SequentialChunkAnalyzerRefusedRecordingTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_conversation_that_ends_after_a_refused_recording_call_is_recorded_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', SequentialChunkAnalyzerHarness::finding('recorded'));
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused'));

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker finding was refused by the recording tool and never recorded again; the chunk is recorded as errored and left out of the cache',
            ['files' => ['src/A.php'], 'findings_kept' => 1, 'refused_calls' => 1],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, $logger)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['recorded'], $this->titles($vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'reason' => 'a finding the record tool refused was never recorded again']], $recordingCoverageRecorder->failureReasons);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_every_refused_recording_call_the_model_never_repeats_is_counted(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused', 11));
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused too', 12));
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused and repeated'));
            $toolRegistry->execute('record_vulnerability', SequentialChunkAnalyzerHarness::finding('refused and repeated'));

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            self::anything(),
            ['files' => ['src/A.php'], 'findings_kept' => 1, 'refused_calls' => 2],
        );

        $this->analyzer($llmClient, $attackerCache, $logger)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_refused_recording_call_the_model_repeats_in_full_leaves_the_chunk_analyzed_and_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('repeated'));
            $toolRegistry->execute('record_vulnerability', SequentialChunkAnalyzerHarness::finding('repeated'));

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['repeated'], $this->titles($vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
        self::assertSame([], $recordingCoverageRecorder->failureReasons);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_chunk_stopped_at_the_tool_cap_after_a_refused_call_keeps_the_cap_as_its_reason(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', self::withoutDescription('refused'));

            return LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $this->analyzer($llmClient, $attackerCache)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'reason' => 'tool-call limit reached (audit.max_tool_iterations)']], $recordingCoverageRecorder->failureReasons);
    }

    private function analyzer(LLMClientInterface $llmClient, AttackerCacheInterface $attackerCache, ?LoggerInterface $logger = null): SequentialChunkAnalyzer
    {
        return SequentialChunkAnalyzerHarness::analyzerRecordingThrough($llmClient, $attackerCache, new DescriptionRequiringToolFactory(), $logger);
    }

    /**
     * @return array<string, mixed>
     */
    private static function withoutDescription(string $title, int $lineStart = 1): array
    {
        $finding = SequentialChunkAnalyzerHarness::finding($title);
        $finding['line_start'] = $lineStart;
        unset($finding['description']);

        return $finding;
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<string>
     */
    private function titles(array $vulnerabilities): array
    {
        return array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities);
    }
}
