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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ConcurrentChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ChunkAnalyzersFilePathTest extends TestCase
{
    private const string ABSOLUTE_PATH = '/app/src/A.php';

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_answer_names_its_finding_by_the_chunk_file(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of((string) json_encode([$this->echoedFinding()]), 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), false)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame(['src/A.php'], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_recorded_finding_is_named_by_the_chunk_file(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', $this->echoedFinding());

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), true)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame(['src/A.php'], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_recorded_in_a_conversation_cut_short_is_named_by_the_chunk_file(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', $this->echoedFinding());

            return LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1));
        });

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), true)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame(['src/A.php'], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_recorded_before_an_abort_is_recovered_under_the_chunk_file_name(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(function (string $system, string $user, ToolRegistry $toolRegistry): never {
            $toolRegistry->execute('record_vulnerability', $this->echoedFinding());

            throw BudgetExceededException::forTokens(10, 5);
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        try {
            SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), true)
                ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));
            self::fail('expected BudgetExceededException');
        } catch (BudgetExceededException) {
            self::assertSame(['src/A.php'], $this->paths($recordingCoverageRecorder->found));
        }
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_served_from_the_cache_is_named_by_the_chunk_file(): void
    {
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn([$this->echoedFinding()]);

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer(self::createStub(LLMClientInterface::class), $attackerCache, false)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame(['src/A.php'], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_recorded_in_a_concurrent_window_is_named_by_the_chunk_file(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(function (array $requests): array {
            foreach ($requests as $request) {
                ConcurrentChunkAnalyzerHarness::registryOf($request)->execute('record_vulnerability', $this->echoedFinding());
            }

            return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        });

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), new RiskMarkerIndex([]));

        self::assertSame(['src/A.php'], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_recorded_in_a_window_that_failed_is_recovered_under_the_chunk_file_name(): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(function (array $requests): never {
            foreach ($requests as $request) {
                ConcurrentChunkAnalyzerHarness::registryOf($request)->execute('record_vulnerability', $this->echoedFinding());
            }

            throw new LLMProviderException('window tore');
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        try {
            ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4)
                ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));
            self::fail('expected LLMProviderException');
        } catch (LLMProviderException) {
            self::assertSame(['src/A.php'], $this->paths($recordingCoverageRecorder->found));
        }
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_finding_served_from_the_cache_to_a_concurrent_window_is_named_by_the_chunk_file(): void
    {
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn([$this->echoedFinding()]);

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzer(self::createStub(ToolBatchCapableLLMClientInterface::class), 4, $attackerCache)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new RecordingCoverageRecorder(), new RiskMarkerIndex([]));

        self::assertSame(['src/A.php'], $this->paths($vulnerabilities));
    }

    /**
     * @return array<string, mixed>
     */
    private function echoedFinding(): array
    {
        return [...SequentialChunkAnalyzerHarness::finding('echoed'), 'file_path' => self::ABSOLUTE_PATH];
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<string>
     */
    private function paths(array $vulnerabilities): array
    {
        return array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->filePath(), $vulnerabilities);
    }
}
