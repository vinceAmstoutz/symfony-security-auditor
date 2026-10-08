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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextKeyDeriver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\SequentialChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMFixedPromptTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture\RecordingProgressReporter;

final class SequentialChunkAnalyzerTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     */
    public function test_an_llm_provider_exception_marks_the_chunk_after_the_failing_one_as_errored(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new LLMProviderException('platform gone'));

        $sequentialChunkAnalyzer = new SequentialChunkAnalyzer(
            $llmClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver()),
            new AttackerChunkCache(new NullAttackerCache(), $this->vulnerabilityFactory(), new NullLogger()),
            $this->vulnerabilityFactory(),
            new NullLogger(),
            new NullProgressReporter(),
            3,
            false,
            null,
        );

        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        try {
            $sequentialChunkAnalyzer->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
                new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())),
                $recordingCoverageRecorder,
                null,
                new RiskMarkerIndex([]),
            );
            self::fail('expected LLMProviderException');
        } catch (LLMProviderException) {
            self::assertSame(
                [
                    ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                    ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
                ],
                $recordingCoverageRecorder->coverage,
            );
        }
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_chunk_stopped_at_the_tool_cap_reports_the_cap_as_the_reason_it_failed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $recordingProgressReporter = new RecordingProgressReporter();

        $this->analyzer($llmClient, $attackerCache, false, progressReporter: $recordingProgressReporter)->analyze([[$this->makeFile('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        $completed = $recordingProgressReporter->eventsNamed('attacker.chunk.completed');
        self::assertCount(1, $completed);
        self::assertSame('errored', $completed[0]['status']);
        self::assertSame('tool-call limit reached (audit.max_tool_iterations)', $completed[0]['reason']);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_chunk_whose_call_failed_reports_the_error_as_the_reason_it_failed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new RuntimeException('connection hiccup'));
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $recordingProgressReporter = new RecordingProgressReporter();

        $this->analyzer($llmClient, $attackerCache, false, progressReporter: $recordingProgressReporter)->analyze([[$this->makeFile('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame('connection hiccup', $recordingProgressReporter->eventsNamed('attacker.chunk.completed')[0]['reason']);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_chunk_answered_with_something_other_than_json_reports_that_as_the_reason_it_failed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('I could not find anything to report.', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $recordingProgressReporter = new RecordingProgressReporter();

        $this->analyzer($llmClient, $attackerCache, false, progressReporter: $recordingProgressReporter)->analyze([[$this->makeFile('src/A.php')]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame('the answer was not valid JSON', $recordingProgressReporter->eventsNamed('attacker.chunk.completed')[0]['reason']);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_single_file_the_model_cannot_fit_reports_that_as_the_reason_its_chunk_failed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new LLMRequestTooLargeException('prompt is too long'));
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $recordingProgressReporter = new RecordingProgressReporter();

        $this->analyzer($llmClient, $attackerCache, false, progressReporter: $recordingProgressReporter)->analyze([[$this->makeFileOfSize('src/A.php', 16384)]], $this->request(), new RecordingCoverageRecorder(), null, new RiskMarkerIndex([]));

        self::assertSame('the file is too large for the model input limit', $recordingProgressReporter->eventsNamed('attacker.chunk.completed')[0]['reason']);
    }

    private function vulnerabilityFactory(): VulnerabilityFactory
    {
        return ChunkAnalysisInputs::vulnerabilityFactory();
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ChunkAnalysisInputs::file($path);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_answer_cut_by_the_token_limit_keeps_its_parseable_findings_but_is_recorded_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of(
            \sprintf('[%s, {"type": "sql_injection", "severity": "high", "title": "cut', (string) json_encode(self::finding('complete finding'))),
            'm',
            'length',
            TokenUsageSnapshot::of(1, 1),
        ));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze([[$this->makeFile('src/A.php')]], $this->request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['complete finding'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_an_empty_answer_stopped_at_the_tool_cap_is_recorded_errored_instead_of_cached_as_safe(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker response was cut short; the chunk is recorded as errored and left out of the cache',
            ['stop_reason' => 'max_tool_iterations', 'files' => ['src/A.php'], 'findings_kept' => 0],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false, $logger)->analyze([[$this->makeFile('src/A.php')]], $this->request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_conversation_stopped_at_the_tool_cap_keeps_the_findings_it_recorded_but_is_errored_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', self::finding('recorded before the cap'));

            return LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, true)->analyze([[$this->makeFile('src/A.php')]], $this->request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['recorded before the cap'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_conversation_that_ended_normally_is_recorded_analyzed_and_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse {
            $toolRegistry->execute('record_vulnerability', self::finding('complete'));

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, true)->analyze([[$this->makeFile('src/A.php')]], $this->request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame(['complete'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }

    private function analyzer(LLMClientInterface $llmClient, AttackerCacheInterface $attackerCache, bool $structured, ?LoggerInterface $logger = null, ?ProgressReporterInterface $progressReporter = null): SequentialChunkAnalyzer
    {
        return SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, $structured, $logger, $progressReporter);
    }

    private function request(): AttackerAnalysisRequest
    {
        return ChunkAnalysisInputs::request();
    }

    /**
     * @return array<string, mixed>
     */
    private static function finding(string $title): array
    {
        return SequentialChunkAnalyzerHarness::finding($title);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_answer_cut_before_its_first_finding_closed_yields_nothing_and_is_recorded_errored(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('[{"type": "sql_injection", "severity": "hi', 'm', 'length', TokenUsageSnapshot::of(1, 1)));
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze([[$this->makeFile('src/A.php')]], $this->request(), $recordingCoverageRecorder, null, new RiskMarkerIndex([]));

        self::assertSame([], $vulnerabilities);
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_large_single_file_the_model_cannot_fit_is_recorded_errored_and_the_next_chunk_is_still_analyzed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('from B');
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => $chunk[0] instanceof ProjectFile && 'src/B.php' === $chunk[0]->relativePath()),
            self::anything(),
        );
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker chunk exceeds the model input limit as a single file; it is recorded as errored and left out of the cache',
            ['files' => ['src/A.php'], 'error' => 'prompt is too long'],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false, $logger)->analyze(
            [[$this->makeFileOfSize('src/A.php', 16384)], [$this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_budget_abort_while_the_first_half_is_analyzed_records_the_second_half_and_the_next_chunk_as_aborted(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/C.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            throw BudgetExceededException::forTokens(150, 100);
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->analyzer($llmClient, new NullAttackerCache(), false)->analyze(
                [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php'), $this->makeFile('src/C.php')], [$this->makeFile('src/D.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                null,
                new RiskMarkerIndex([]),
            );
        } catch (BudgetExceededException $budgetExceededException) {
            $caught = $budgetExceededException;
        }

        self::assertInstanceOf(BudgetExceededException::class, $caught);
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'aborted'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'aborted'],
                ['stage' => 'attacker', 'filePath' => 'src/C.php', 'status' => 'aborted'],
                ['stage' => 'attacker', 'filePath' => 'src/D.php', 'status' => 'aborted'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_provider_failure_while_the_first_half_is_analyzed_records_the_second_half_and_the_next_chunk_as_errored(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/C.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            throw new LLMProviderException('platform gone');
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->analyzer($llmClient, new NullAttackerCache(), false)->analyze(
                [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php'), $this->makeFile('src/C.php')], [$this->makeFile('src/D.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                null,
                new RiskMarkerIndex([]),
            );
        } catch (LLMProviderException $llmProviderException) {
            $caught = $llmProviderException;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/C.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/D.php', 'status' => 'errored'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function jsonAnswer(string $title): LLMResponse
    {
        return SequentialChunkAnalyzerHarness::jsonAnswer($title);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_small_single_file_the_model_cannot_fit_stops_the_run_naming_the_fixed_prompt_as_the_cause(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('never reached');
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->analyzer($llmClient, new NullAttackerCache(), false)->analyze(
                [[$this->makeFileOfSize('src/A.php', 100)], [$this->makeFile('src/B.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                null,
                new RiskMarkerIndex([]),
            );
        } catch (LLMFixedPromptTooLargeException $llmFixedPromptTooLargeException) {
            $caught = $llmFixedPromptTooLargeException;
        }

        self::assertInstanceOf(LLMFixedPromptTooLargeException::class, $caught);
        self::assertStringContainsString('even with only the 100-byte file "src/A.php" in it (prompt is too long)', $caught->getMessage());
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_mid_size_file_that_is_most_of_the_refused_prompt_is_recorded_errored_rather_than_stopping_the_run(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('from B');
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, new NullAttackerCache(), false)->analyze(
            [[$this->makeFileOfSize('src/A.php', 12000)], [$this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFileOfSize(string $path, int $bytes): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, str_repeat('x', $bytes));
    }
}
