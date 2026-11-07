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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Critic;

use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageCritic;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageCriticSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CoverageCriticPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\CoverageCriticPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordCoverageGapToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class CoverageCriticTest extends TestCase
{
    private const string EXPORT_CONTROLLER = 'src/Controller/ExportController.php';

    private const string EXPORT_HANDLER = 'src/MessageHandler/ExportHandler.php';

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_the_gap_the_model_records(): void
    {
        $auditContext = $this->auditContext();

        $gaps = $this->critic($this->recordingClient([self::gap([self::EXPORT_CONTROLLER, self::EXPORT_HANDLER])]))->gaps($this->mapping(), $auditContext);

        self::assertEquals([new CoverageGap($auditContext->projectFiles(), 'The bulk export skips the owner check.', 'broken_access_control')], $gaps);
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_gap_naming_a_file_the_run_did_not_audit_is_dropped(): void
    {
        $auditContext = $this->auditContext();

        $gaps = $this->critic($this->recordingClient([
            self::gap([self::EXPORT_CONTROLLER, 'src/Controller/ImportController.php'], 'The import trusts the owner id.'),
            self::gap([self::EXPORT_HANDLER]),
        ]))->gaps($this->mapping(), $auditContext);

        self::assertEquals([new CoverageGap([$auditContext->projectFiles()[1]], 'The bulk export skips the owner check.', 'broken_access_control')], $gaps);
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_it_keeps_the_first_gaps_up_to_the_most_it_may_name(): void
    {
        $gaps = $this->critic(
            $this->recordingClient([self::gap([self::EXPORT_CONTROLLER], 'first'), self::gap([self::EXPORT_HANDLER], 'second'), self::gap([self::EXPORT_CONTROLLER], 'third')]),
            coverageCriticSettings: new CoverageCriticSettings(maxGaps: 2),
        )->gaps($this->mapping(), $this->auditContext());

        self::assertSame(['first', 'second'], array_map(static fn (CoverageGap $coverageGap): string => $coverageGap->hypothesis, $gaps));
    }

    /**
     * @param array<string, mixed> $recordedGap
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('malformedGaps')]
    public function test_a_malformed_gap_is_dropped(array $recordedGap): void
    {
        self::assertSame([], $this->critic($this->recordingClient([$recordedGap]))->gaps($this->mapping(), $this->auditContext()));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function malformedGaps(): iterable
    {
        yield 'files that are no list' => [['files' => self::EXPORT_CONTROLLER, 'hypothesis' => 'h', 'attack_class' => 'idor']];
        yield 'no file' => [self::gap([])];
        yield 'a path that is no text beside an audited one' => [self::gap([self::EXPORT_CONTROLLER, 42])];
        yield 'a blank hypothesis' => [self::gap([self::EXPORT_CONTROLLER], ' ')];
        yield 'a blank attack class' => [self::gap([self::EXPORT_CONTROLLER], 'h', ' ')];
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws JsonException
     * @throws InvalidTokenUsageException
     */
    public function test_with_structured_collection_off_it_reads_the_gaps_from_a_json_answer(): void
    {
        $auditContext = $this->auditContext();
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(self::response(json_encode([self::gap([self::EXPORT_HANDLER])], \JSON_THROW_ON_ERROR)));

        $gaps = $this->critic($llmClient, coverageCriticSettings: new CoverageCriticSettings(structuredCollection: false))->gaps($this->mapping(), $auditContext);

        self::assertEquals([new CoverageGap([$auditContext->projectFiles()[1]], 'The bulk export skips the owner check.', 'broken_access_control')], $gaps);
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws JsonException
     * @throws InvalidTokenUsageException
     */
    public function test_it_reads_the_answer_as_json_when_the_client_never_offered_the_recording_tool(): void
    {
        $auditContext = $this->auditContext();
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturn(self::response(json_encode([self::gap([self::EXPORT_HANDLER])], \JSON_THROW_ON_ERROR)));

        $gaps = $this->critic($llmClient)->gaps($this->mapping(), $auditContext);

        self::assertEquals([new CoverageGap([$auditContext->projectFiles()[1]], 'The bulk export skips the owner check.', 'broken_access_control')], $gaps);
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws JsonException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('malformedAnsweredGaps')]
    public function test_a_malformed_gap_in_a_json_answer_is_dropped(mixed $answeredGap): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(self::response(json_encode([$answeredGap], \JSON_THROW_ON_ERROR)));

        self::assertSame([], $this->critic($llmClient, coverageCriticSettings: new CoverageCriticSettings(structuredCollection: false))->gaps($this->mapping(), $this->auditContext()));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function malformedAnsweredGaps(): iterable
    {
        yield 'a gap that is no object' => [self::EXPORT_CONTROLLER];
        yield 'no files' => [['hypothesis' => 'h', 'attack_class' => 'idor']];
        yield 'no hypothesis' => [['files' => [self::EXPORT_CONTROLLER], 'attack_class' => 'idor']];
        yield 'a hypothesis that is no text' => [['files' => [self::EXPORT_CONTROLLER], 'hypothesis' => 42, 'attack_class' => 'idor']];
        yield 'no attack class' => [['files' => [self::EXPORT_CONTROLLER], 'hypothesis' => 'h']];
        yield 'an attack class that is no text' => [['files' => [self::EXPORT_CONTROLLER], 'hypothesis' => 'h', 'attack_class' => 42]];
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('echoedSpellings')]
    public function test_a_path_echoed_in_another_spelling_names_the_audited_file(string $echoedPath): void
    {
        $auditContext = $this->auditContext();

        $gaps = $this->critic($this->recordingClient([self::gap([$echoedPath])]))->gaps($this->mapping(), $auditContext);

        self::assertEquals([new CoverageGap([$auditContext->projectFiles()[1]], 'The bulk export skips the owner check.', 'broken_access_control')], $gaps);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function echoedSpellings(): iterable
    {
        yield 'with a leading ./' => ['./'.self::EXPORT_HANDLER];
        yield 'absolute' => ['/app/'.self::EXPORT_HANDLER];
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     */
    public function test_it_spends_no_call_on_a_run_that_audited_no_file(): void
    {
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');

        self::assertSame([], $this->critic($llmClient)->gaps($this->mapping(), AuditContext::forProject(sys_get_temp_dir())));
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     */
    public function test_an_answer_it_cannot_read_names_no_gap_and_is_logged(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(self::response('No gap worth naming.'));
        $warningCollectingLogger = new WarningCollectingLogger();

        $gaps = $this->critic($llmClient, $warningCollectingLogger, new CoverageCriticSettings(structuredCollection: false))->gaps($this->mapping(), $this->auditContext());

        self::assertSame([[], [['The coverage critic failed, so no gap is analyzed', ['error' => 'Syntax error']]]], [$gaps, $warningCollectingLogger->warnings]);
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('failuresThatStopTheRun')]
    public function test_a_failure_that_stops_the_run_is_rethrown(RuntimeException $runtimeException): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException($runtimeException);

        $this->expectExceptionObject($runtimeException);

        $this->critic($llmClient)->gaps($this->mapping(), $this->auditContext());
    }

    /**
     * @return iterable<string, array{RuntimeException}>
     */
    public static function failuresThatStopTheRun(): iterable
    {
        yield 'a provider failure that repeats on every call' => [new LLMProviderException('Invalid API key.')];
        yield 'the budget spent' => [BudgetExceededException::forTokens(10, 5)];
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_summary_the_model_cannot_fit_names_no_gap_and_is_logged(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(LLMRequestTooLargeException::fromProviderRejection(new RuntimeException('prompt is too long')));
        $warningCollectingLogger = new WarningCollectingLogger();

        $gaps = $this->critic($llmClient, $warningCollectingLogger)->gaps($this->mapping(), $this->auditContext());

        self::assertSame([[], [['The coverage critic failed, so no gap is analyzed', ['error' => 'The model cannot fit the request: prompt is too long']]]], [$gaps, $warningCollectingLogger->warnings]);
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_model_may_take_a_tool_round_per_gap_and_one_more_to_finish(): void
    {
        $toolRounds = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations) use (&$toolRounds): LLMResponse {
                $toolRounds[] = $maxToolIterations;

                return self::response('');
            },
        );

        $this->critic($llmClient, coverageCriticSettings: new CoverageCriticSettings(maxGaps: 3))->gaps($this->mapping(), $this->auditContext());

        self::assertSame([4], $toolRounds);
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('collectionModes')]
    public function test_the_model_reads_its_limit_and_the_groups_the_chunker_makes_of_the_audited_files(bool $structuredCollection, string $method, string $expectedInstruction): void
    {
        $prompts = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method($method)->willReturnCallback(
            static function (string $systemPrompt, string $userMessage) use (&$prompts): LLMResponse {
                $prompts[] = [$systemPrompt, $userMessage];

                return self::response('[]');
            },
        );
        $coverageCritic = new CoverageCritic($llmClient, new CoverageCriticPromptBuilder(), new RecordCoverageGapToolFactory(), new FileChunker(ChunkingStrategy::Type, 1), new NullLogger(), new CoverageCriticSettings(2, $structuredCollection));

        $coverageCritic->gaps($this->mapping(), $this->auditContext());

        self::assertSame(
            [true, true, true],
            [
                str_contains($prompts[0][0] ?? '', 'name at most 2 gaps'),
                str_contains($prompts[0][0] ?? '', $expectedInstruction),
                str_contains($prompts[0][1] ?? '', \sprintf("- %s (not analyzed)\n- %s (not analyzed)", self::EXPORT_CONTROLLER, self::EXPORT_HANDLER)),
            ],
        );
    }

    /**
     * @return iterable<string, array{bool, string, string}>
     */
    public static function collectionModes(): iterable
    {
        yield 'recorded through the tool' => [true, 'completeWithTools', 'Record each gap with one `record_coverage_gap` call'];
        yield 'answered as JSON' => [false, 'complete', 'Answer with ONLY a JSON array'];
    }

    /**
     * @param list<mixed> $files
     *
     * @return array<string, mixed>
     */
    private static function gap(array $files, string $hypothesis = 'The bulk export skips the owner check.', string $attackClass = 'broken_access_control'): array
    {
        return ['files' => $files, 'hypothesis' => $hypothesis, 'attack_class' => $attackClass];
    }

    /**
     * @param list<array<string, mixed>> $recordedGaps
     */
    private function recordingClient(array $recordedGaps): LLMClientInterface
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry) use ($recordedGaps): LLMResponse {
                foreach ($recordedGaps as $recordedGap) {
                    $toolRegistry->execute('record_coverage_gap', $recordedGap);
                }

                return self::response('');
            },
        );

        return $llmClient;
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function response(string $content): LLMResponse
    {
        return LLMResponse::of($content, 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    private function critic(LLMClientInterface $llmClient, ?LoggerInterface $logger = null, CoverageCriticSettings $coverageCriticSettings = new CoverageCriticSettings()): CoverageCritic
    {
        return new CoverageCritic(
            $llmClient,
            self::createStub(CoverageCriticPromptBuilderInterface::class),
            new RecordCoverageGapToolFactory(),
            new FileChunker(),
            $logger ?? new NullLogger(),
            $coverageCriticSettings,
        );
    }

    private function mapping(): SymfonyMapping
    {
        return SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function auditContext(): AuditContext
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setProjectFiles([
            ProjectFile::create(self::EXPORT_CONTROLLER, '/app/'.self::EXPORT_CONTROLLER, '<?php class ExportController {}'),
            ProjectFile::create(self::EXPORT_HANDLER, '/app/'.self::EXPORT_HANDLER, '<?php class ExportHandler {}'),
        ]);

        return $auditContext;
    }
}
