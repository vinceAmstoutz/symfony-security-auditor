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
use Symfony\Component\Validator\Validation;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

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

    private function vulnerabilityFactory(): VulnerabilityFactory
    {
        return new VulnerabilityFactory(new NullLogger(), Validation::createValidator());
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
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

    private function analyzer(LLMClientInterface $llmClient, AttackerCacheInterface $attackerCache, bool $structured, ?LoggerInterface $logger = null): SequentialChunkAnalyzer
    {
        return new SequentialChunkAnalyzer(
            $llmClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver()),
            new AttackerChunkCache($attackerCache, $this->vulnerabilityFactory(), new NullLogger()),
            $this->vulnerabilityFactory(),
            $logger ?? new NullLogger(),
            new NullProgressReporter(),
            3,
            $structured,
            $structured ? new RecordVulnerabilityToolFactory() : null,
        );
    }

    private function request(): AttackerAnalysisRequest
    {
        return new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));
    }

    /**
     * @return array<string, mixed>
     */
    private static function finding(string $title): array
    {
        return [
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => $title,
            'description' => 'desc',
            'file_path' => 'src/A.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.9,
        ];
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
    public function test_a_chunk_the_model_cannot_fit_is_split_in_two_and_each_half_analyzed_on_its_own(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            $files = array_values(array_filter(['src/A.php', 'src/B.php', 'src/C.php'], static fn (string $file): bool => str_contains($user, $file)));
            if (3 === \count($files)) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('from '.implode('+', $files));
        });
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker chunk exceeds the model input limit; it is split in two and each half analyzed on its own',
            ['files' => ['src/A.php', 'src/B.php', 'src/C.php'], 'error' => 'prompt is too long'],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, new NullAttackerCache(), false, $logger)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php'), $this->makeFile('src/C.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from src/A.php+src/B.php', 'from src/C.php'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/C.php', 'status' => 'analyzed'],
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
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_half_of_a_split_chunk_already_in_the_cache_is_served_without_a_provider_call(): void
    {
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::exactly(2))->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('from A');
        });
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturnCallback(
            static fn (array $chunk): ?array => 1 === \count($chunk) && $chunk[0] instanceof ProjectFile && 'src/B.php' === $chunk[0]->relativePath() ? [self::finding('cached B')] : null,
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'cached B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'cached'],
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
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_the_findings_of_both_halves_are_cached_under_the_whole_chunk_so_the_next_run_does_not_send_it_again(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer(str_contains($user, 'src/A.php') ? 'from A' : 'from B');
        });
        $stored = [];
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->method('store')->willReturnCallback(static function (array $chunk, array $rawVulnerabilities) use (&$stored): void {
            $stored[] = [self::pathsOf($chunk), array_column($rawVulnerabilities, 'title', 'file_path')];
        });

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                [['src/A.php'], ['src/A.php' => 'from A']],
                [['src/B.php'], ['src/A.php' => 'from B']],
                [['src/A.php', 'src/B.php'], ['src/A.php' => 'from B']],
            ],
            $stored,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_split_chunk_is_not_cached_whole_when_caching_is_bypassed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer(str_contains($user, 'src/A.php') ? 'from A' : 'from B');
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), true),
            new RecordingCoverageRecorder(),
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_split_chunk_is_not_cached_whole_when_a_half_came_back_cut_short(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            if (str_contains($user, 'src/B.php')) {
                return LLMResponse::of((string) json_encode([self::finding('from B')]), 'm', 'length', TokenUsageSnapshot::of(1, 1));
            }

            return self::jsonAnswer('from A');
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => 1 === \count($chunk) && $chunk[0] instanceof ProjectFile && 'src/A.php' === $chunk[0]->relativePath()),
            self::anything(),
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function jsonAnswer(string $title): LLMResponse
    {
        return LLMResponse::of((string) json_encode([self::finding($title)]), 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
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

    /**
     * @return list<string>
     */
    private static function pathsOf(mixed $chunk): array
    {
        self::assertIsArray($chunk);
        $paths = [];
        foreach ($chunk as $file) {
            self::assertInstanceOf(ProjectFile::class, $file);
            $paths[] = $file->relativePath();
        }

        return $paths;
    }
}
