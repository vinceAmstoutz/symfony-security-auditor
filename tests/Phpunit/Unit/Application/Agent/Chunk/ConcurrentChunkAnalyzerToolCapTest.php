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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ConcurrentChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ConcurrentChunkAnalyzerToolCapTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_window_entry_that_reached_the_tool_cap_is_cached_only_with_a_finding(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            ConcurrentChunkAnalyzerHarness::registryOf($requests[0])->definitions();
            ConcurrentChunkAnalyzerHarness::registryOf($requests[1])->execute('record_vulnerability', ConcurrentChunkAnalyzerHarness::recordedFinding('recorded at the cap'));

            return [
                LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))->withReachedToolCap(),
                LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))->withReachedToolCap(),
            ];
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4, $this->cacheStoringOnlyFile('src/B.php'))
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['recorded at the cap'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['analyzed' => 2], ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php']], $recordingCoverageRecorder->inconclusive);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_text_answer_without_a_finding_from_a_client_that_ignores_the_recording_tool_is_left_out_of_the_cache_at_the_tool_cap(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturn([
            LLMResponse::of('[]', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))->withReachedToolCap(),
            LLMResponse::of('[]', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
        ]);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4, $this->cacheStoringOnlyFile('src/B.php'))
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));

        self::assertSame(['analyzed' => 2], ConcurrentChunkAnalyzerHarness::statusCounts($recordingCoverageRecorder));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php']], $recordingCoverageRecorder->inconclusive);
    }

    private function cacheStoringOnlyFile(string $path): AttackerCacheInterface
    {
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => $chunk[0] instanceof ProjectFile && $path === $chunk[0]->relativePath()),
            self::anything(),
        );

        return $attackerCache;
    }
}
