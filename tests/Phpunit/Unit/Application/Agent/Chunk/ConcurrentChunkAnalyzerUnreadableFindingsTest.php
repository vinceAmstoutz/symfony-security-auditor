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

final class ConcurrentChunkAnalyzerUnreadableFindingsTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_chunk_that_recorded_an_entry_that_cannot_be_read_keeps_the_others_but_is_errored_and_not_cached_while_its_sibling_is_analyzed_and_cached(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests): array {
            $toolRegistry = ConcurrentChunkAnalyzerHarness::registryOf($requests[0]);
            $toolRegistry->execute('record_vulnerability', ConcurrentChunkAnalyzerHarness::recordedFinding('readable'));
            $toolRegistry->execute('record_vulnerability', [...ConcurrentChunkAnalyzerHarness::recordedFinding('unreadable'), 'type' => 'not_a_type']);
            ConcurrentChunkAnalyzerHarness::registryOf($requests[1])->execute('record_vulnerability', ConcurrentChunkAnalyzerHarness::recordedFinding('clean sibling'));

            return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => 1 === \count($chunk) && $chunk[0] instanceof ProjectFile && 'src/B.php' === $chunk[0]->relativePath()),
            self::anything(),
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 2, $attackerCache)->analyze(
            [[ChunkAnalysisInputs::file('src/A.php')], [ChunkAnalysisInputs::file('src/B.php')]],
            ChunkAnalysisInputs::request(),
            $recordingCoverageRecorder,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['readable', 'clean sibling'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(['hydration_failed' => 1], $drops);
        self::assertSame(
            [['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'], ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed']],
            $recordingCoverageRecorder->coverage,
        );
    }
}
