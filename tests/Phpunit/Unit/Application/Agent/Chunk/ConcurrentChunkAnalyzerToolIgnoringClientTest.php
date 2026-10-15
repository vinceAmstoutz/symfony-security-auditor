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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ConcurrentChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ConcurrentChunkAnalyzerToolIgnoringClientTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_client_that_never_offers_the_recording_tool_has_each_answer_read_as_a_json_answer(): void
    {
        $answers = [
            SequentialChunkAnalyzerHarness::jsonAnswer('answered as text'),
            LLMResponse::of('src/B.php builds its SQL query from the request.', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
            LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
        ];
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturn($answers);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')], [ChunkAnalysisInputs::file('src/C.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['answered as text'], $this->titles($vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/C.php', 'status' => 'analyzed'],
            ],
            $recordingCoverageRecorder->coverage,
        );
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/B.php', 'reason' => 'the answer was not valid JSON']], $recordingCoverageRecorder->failureReasons);
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
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests) use ($llmResponse): array {
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->definitions();

            return [$llmResponse];
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
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
