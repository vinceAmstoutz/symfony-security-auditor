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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ConcurrentChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SchemaCachingClientChunkTest extends TestCase
{
    private const string CLEAN_VERDICT = 'No exploitable vulnerability in this chunk.';

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_client_that_offered_the_tool_schemas_it_built_once_has_every_later_clean_chunk_recorded_analyzed(): void
    {
        $schemas = null;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use (&$schemas): LLMResponse {
            $schemas ??= $toolRegistry->definitions();

            return self::cleanVerdict();
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        SequentialChunkAnalyzerHarness::analyzer($llmClient, new NullAttackerCache(), true)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_batch_client_that_offered_the_tool_schemas_of_its_first_request_only_has_every_clean_chunk_recorded_analyzed(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->definitions();

            return array_fill(0, \count($requests), self::cleanVerdict());
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['analyzed' => 2], ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_batch_client_that_offered_the_tool_schemas_in_an_earlier_window_has_every_later_clean_chunk_recorded_analyzed(): void
    {
        $schemas = null;
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests) use (&$schemas): array {
            $schemas ??= ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->definitions();

            return array_fill(0, \count($requests), self::cleanVerdict());
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 1)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['analyzed' => 2], ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function cleanVerdict(): LLMResponse
    {
        return LLMResponse::of(self::CLEAN_VERDICT, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
    }
}
