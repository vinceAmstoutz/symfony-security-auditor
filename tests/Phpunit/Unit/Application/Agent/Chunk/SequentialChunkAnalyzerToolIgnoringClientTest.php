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

final class SequentialChunkAnalyzerToolIgnoringClientTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_client_that_never_offers_the_recording_tool_has_the_findings_of_its_json_answer_kept(): void
    {
        $llmResponse = SequentialChunkAnalyzerHarness::jsonAnswer('answered as text');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn($llmResponse);
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $attackerCache, $recordingCoverageRecorder);

        self::assertSame(['answered as text'], $this->titles($vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_client_that_never_offers_the_recording_tool_and_answers_prose_has_its_chunk_recorded_errored(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::of('src/A.php builds its SQL query from the request.', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $attackerCache, $recordingCoverageRecorder);

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'reason' => 'the answer was not valid JSON']], $recordingCoverageRecorder->failureReasons);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_client_that_never_offers_the_recording_tool_and_answers_nothing_has_its_chunk_recorded_analyzed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $attackerCache, $recordingCoverageRecorder);

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_client_that_offers_the_recording_tool_has_its_answer_text_left_unread(): void
    {
        $llmResponse = SequentialChunkAnalyzerHarness::jsonAnswer('answered as text');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($llmResponse): LLMResponse {
            $toolRegistry->definitions();

            return $llmResponse;
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $attackerCache, $recordingCoverageRecorder);

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @return list<Vulnerability>
     *
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function analyze(LLMClientInterface $llmClient, AttackerCacheInterface $attackerCache, RecordingCoverageRecorder $recordingCoverageRecorder): array
    {
        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, true)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        return $vulnerabilities;
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
