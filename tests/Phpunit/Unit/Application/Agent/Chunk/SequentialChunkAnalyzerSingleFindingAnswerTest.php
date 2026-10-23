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
        yield 'an object in a fence' => ["```json\n".$finding."\n```"];
        yield 'an object after prose citing bracketed references' => ["I found one issue [1] in [the login form]:\n\n".$finding];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function answersHoldingFindingsApart(): iterable
    {
        $sqli = (string) json_encode(SequentialChunkAnalyzerHarness::finding('SQLi'));
        $xss = (string) json_encode([...SequentialChunkAnalyzerHarness::finding('XSS'), 'type' => 'xss']);

        yield 'one object per line' => [$sqli."\n".$xss];
        yield 'objects between prose' => ["Finding 1:\n".$sqli."\n\nFinding 2:\n".$xss];
        yield 'an array then one more object' => ['['.$sqli."]\n\nAlso:\n".$xss];
        yield 'an array cut off' => ['['.$sqli.','.$xss.',{"type":"csrf","title":"CS'];
        yield 'an object then one cut off' => [$sqli.'{"type":"xss","ti'];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('answersHoldingFindingsApart')]
    public function test_a_json_answer_holding_findings_outside_one_array_leaves_the_chunk_errored_and_out_of_the_cache(string $answer): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of($answer, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, false)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_object_keyed_by_finding_is_read_as_its_findings_and_the_chunk_is_analyzed_and_cached(): void
    {
        $sqli = SequentialChunkAnalyzerHarness::finding('SQLi');
        $xss = [...SequentialChunkAnalyzerHarness::finding('XSS'), 'type' => 'xss'];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of((string) json_encode(['finding_1' => $sqli, 'finding_2' => $xss]), 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(self::anything(), [$sqli, $xss]);
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities, $drops] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, false)->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['SQLi', 'XSS'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
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
