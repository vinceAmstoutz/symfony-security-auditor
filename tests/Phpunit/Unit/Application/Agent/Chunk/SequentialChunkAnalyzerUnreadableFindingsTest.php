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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SequentialChunkAnalyzerUnreadableFindingsTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_answer_with_an_entry_that_cannot_be_read_keeps_the_others_but_is_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of(
            (string) json_encode([SequentialChunkAnalyzerHarness::finding('readable'), [...SequentialChunkAnalyzerHarness::finding('unreadable'), 'type' => 'not_a_type']]),
            'm',
            'end_turn',
            TokenUsageSnapshot::of(1, 1),
        ));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, false)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['readable'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['hydration_failed' => 1], $drops);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_answer_with_a_confidence_that_cannot_be_read_keeps_the_others_but_is_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of(
            (string) json_encode([SequentialChunkAnalyzerHarness::finding('readable'), [...SequentialChunkAnalyzerHarness::finding('unreadable'), 'confidence' => '90%']]),
            'm',
            'end_turn',
            TokenUsageSnapshot::of(1, 1),
        ));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, false)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['readable'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['hydration_failed' => 1], $drops);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_answer_holding_a_bare_string_among_its_findings_is_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of(
            (string) json_encode([SequentialChunkAnalyzerHarness::finding('readable'), 'SQL injection in src/A.php']),
            'm',
            'end_turn',
            TokenUsageSnapshot::of(1, 1),
        ));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, false)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertCount(1, $vulnerabilities);
        self::assertSame(['non_array_entry' => 1], $drops);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_conversation_that_recorded_an_entry_that_cannot_be_read_keeps_the_others_but_is_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', SequentialChunkAnalyzerHarness::finding('readable'));
            $toolRegistry->execute('record_vulnerability', [...SequentialChunkAnalyzerHarness::finding('unreadable'), 'file_path' => '']);

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, true)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['readable'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['validation_failed' => 1], $drops);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_conversation_whose_entry_only_needed_normalising_is_analyzed_and_cached_with_what_the_model_recorded(): void
    {
        $entry = [...SequentialChunkAnalyzerHarness::finding('long proof'), 'proof' => str_repeat('p', 5001), 'severity' => 'HIGH', 'confidence' => 85];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($entry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', $entry);

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(self::anything(), [$entry]);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, true)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['long proof'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame([], $drops);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_the_warning_names_the_files_of_the_chunk_and_what_was_dropped(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of(
            (string) json_encode([[...SequentialChunkAnalyzerHarness::finding('unreadable'), 'type' => 'not_a_type'], 'bare string', 7]),
            'm',
            'end_turn',
            TokenUsageSnapshot::of(1, 1),
        ));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker answer held entries that could not be read as findings; the chunk is recorded as errored and left out of the cache',
            ['files' => ['src/A.php', 'src/B.php'], 'dropped' => ['hydration_failed' => 1, 'non_array_entry' => 2]],
        );

        SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), false, $logger)->analyze(
            [[ChunkAnalysisInputs::file('src/A.php'), ChunkAnalysisInputs::file('src/B.php')]],
            ChunkAnalysisInputs::request(),
            new RecordingCoverageRecorder(),
            null,
            new RiskMarkerIndex([]),
        );
    }
}
