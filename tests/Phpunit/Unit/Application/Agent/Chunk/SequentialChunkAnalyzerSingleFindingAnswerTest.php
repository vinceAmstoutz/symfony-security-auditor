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

use PHPUnit\Framework\Attributes\DataProvider;
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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SequentialChunkAnalyzerSingleFindingAnswerTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function singleFindingAnswers(): iterable
    {
        $finding = (string) json_encode(SequentialChunkAnalyzerHarness::finding('the only finding'));

        yield 'a bare object' => [$finding];
        yield 'an object after prose' => ["I found one issue:\n\n".$finding];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('singleFindingAnswers')]
    public function test_a_json_answer_that_is_one_finding_object_is_read_as_that_finding_and_the_chunk_is_analyzed_and_cached(string $answer): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of($answer, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(self::anything(), [SequentialChunkAnalyzerHarness::finding('the only finding')]);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, false)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['the only finding'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame([], $drops);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }
}
