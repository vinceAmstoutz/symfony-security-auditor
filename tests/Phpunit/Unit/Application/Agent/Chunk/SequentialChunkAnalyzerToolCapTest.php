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

final class SequentialChunkAnalyzerToolCapTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('answersWithoutAFinding')]
    public function test_a_json_answer_that_reached_the_tool_cap_without_a_finding_is_analyzed_but_left_out_of_the_cache(string $content): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of($content, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))->withReachedToolCap());
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('info')->with(
            'Attacker reached its last tool round without a finding; the chunk is recorded as analyzed and left out of the cache, so the next run looks again',
            ['files' => ['src/A.php']],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $this->cacheNeverStoring(), false, $recordingCoverageRecorder, $logger);

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php']], $recordingCoverageRecorder->inconclusive);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function answersWithoutAFinding(): iterable
    {
        yield 'an empty array' => ['[]'];
        yield 'no text at all' => [''];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_answer_that_reached_the_tool_cap_with_a_finding_is_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(SequentialChunkAnalyzerHarness::jsonAnswer('found at the cap')->withReachedToolCap());
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $this->cacheStoringOnce(), false, $recordingCoverageRecorder);

        self::assertSame(['found at the cap'], $this->titles($vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
        self::assertSame([], $recordingCoverageRecorder->inconclusive);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_structured_conversation_that_reached_the_tool_cap_without_a_finding_is_analyzed_but_left_out_of_the_cache(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->definitions();

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))->withReachedToolCap();
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $this->cacheNeverStoring(), true, $recordingCoverageRecorder);

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php']], $recordingCoverageRecorder->inconclusive);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_structured_conversation_that_reached_the_tool_cap_with_a_finding_is_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', SequentialChunkAnalyzerHarness::finding('recorded at the cap'));

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))->withReachedToolCap();
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $this->cacheStoringOnce(), true, $recordingCoverageRecorder);

        self::assertSame(['recorded at the cap'], $this->titles($vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
        self::assertSame([], $recordingCoverageRecorder->inconclusive);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_an_answer_without_a_finding_that_ended_before_the_tool_cap_is_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[]', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($llmClient, $this->cacheStoringOnce(), false, $recordingCoverageRecorder);

        self::assertSame([], $vulnerabilities);
        self::assertSame([], $recordingCoverageRecorder->inconclusive);
    }

    /**
     * @return list<Vulnerability>
     *
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function analyze(LLMClientInterface $llmClient, AttackerCacheInterface $attackerCache, bool $structured, RecordingCoverageRecorder $recordingCoverageRecorder, ?LoggerInterface $logger = null): array
    {
        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, $structured, $logger)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        return $vulnerabilities;
    }

    private function cacheNeverStoring(): AttackerCacheInterface
    {
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');

        return $attackerCache;
    }

    private function cacheStoringOnce(): AttackerCacheInterface
    {
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');

        return $attackerCache;
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
