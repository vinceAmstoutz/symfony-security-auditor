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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
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
    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_json_answer_names_its_finding_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of((string) json_encode([$this->echoedFinding($echoedPath)]), 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), false)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_recorded_finding_is_named_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(function (string $system, string $user, ToolRegistry $toolRegistry) use ($echoedPath): LLMResponse {
            $toolRegistry->execute('record_vulnerability', $this->echoedFinding($echoedPath));

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), true)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_finding_recorded_in_a_conversation_cut_short_is_named_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(function (string $system, string $user, ToolRegistry $toolRegistry) use ($echoedPath): LLMResponse {
            $toolRegistry->execute('record_vulnerability', $this->echoedFinding($echoedPath));

            return LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1));
        });

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), true)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_json_answer_cut_short_names_its_finding_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of(\sprintf('[%s, {"type": "sql_injection", "title": "cut', (string) json_encode($this->echoedFinding($echoedPath))), 'm', 'length', TokenUsageSnapshot::of(1, 1)));

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), false)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_finding_recorded_beside_a_refused_call_is_named_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(function (string $system, string $user, ToolRegistry $toolRegistry) use ($echoedPath): LLMResponse {
            $toolRegistry->execute('record_vulnerability', $this->echoedFinding($echoedPath));
            $refused = SequentialChunkAnalyzerHarness::finding('refused');
            unset($refused['description']);
            $toolRegistry->execute('record_vulnerability', $refused);

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), true)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_finding_recorded_before_an_abort_is_recovered_under_the_name_of_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(function (string $system, string $user, ToolRegistry $toolRegistry) use ($echoedPath): never {
            $toolRegistry->execute('record_vulnerability', $this->echoedFinding($echoedPath));

            throw BudgetExceededException::forTokens(10, 5);
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        try {
            SequentialChunkAnalyzerHarness::analyzer($llmClient, self::createStub(AttackerCacheInterface::class), true)
                ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));
            self::fail('expected BudgetExceededException');
        } catch (BudgetExceededException) {
            self::assertSame([$namedPath], $this->paths($recordingCoverageRecorder->found));
        }
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_finding_served_from_the_cache_is_named_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn([$this->echoedFinding($echoedPath)]);

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzer(self::createStub(LLMClientInterface::class), $attackerCache, false)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_finding_recorded_in_a_concurrent_window_is_named_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(function (array $requests) use ($echoedPath): array {
            foreach ($requests as $request) {
                ConcurrentChunkAnalyzerHarness::registryOf($request)->execute('record_vulnerability', $this->echoedFinding($echoedPath));
            }

            return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        });

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_finding_recorded_in_a_window_that_failed_is_recovered_under_the_name_of_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(function (array $requests) use ($echoedPath): never {
            foreach ($requests as $request) {
                ConcurrentChunkAnalyzerHarness::registryOf($request)->execute('record_vulnerability', $this->echoedFinding($echoedPath));
            }

            throw new LLMProviderException('window tore');
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        try {
            ConcurrentChunkAnalyzerHarness::analyzer($llmClient, 4)
                ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), $recordingCoverageRecorder, new RiskMarkerIndex([]));
            self::fail('expected LLMProviderException');
        } catch (LLMProviderException) {
            self::assertSame([$namedPath], $this->paths($recordingCoverageRecorder->found));
        }
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('echoedFiles')]
    public function test_a_finding_served_from_the_cache_to_a_concurrent_window_is_named_by_the_file_it_denotes(string $echoedPath, string $namedPath): void
    {
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn([$this->echoedFinding($echoedPath)]);

        [$vulnerabilities] = ConcurrentChunkAnalyzerHarness::analyzer(self::createStub(ToolBatchCapableLLMClientInterface::class), 4, $attackerCache)
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), new RiskMarkerIndex([]));

        self::assertSame([$namedPath], $this->paths($vulnerabilities));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function echoedFiles(): iterable
    {
        yield 'a file of the chunk' => ['/app/src/A.php', 'src/A.php'];
        yield 'a file of the pass outside the chunk' => ['/app/src/B.php', 'src/B.php'];
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function request(): AttackerAnalysisRequest
    {
        return new AttackerAnalysisRequest([ChunkAnalysisInputs::file('src/B.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));
    }

    /**
     * @return array<string, mixed>
     */
    private function echoedFinding(string $echoedPath): array
    {
        return [...SequentialChunkAnalyzerHarness::finding('echoed'), 'file_path' => $echoedPath];
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
