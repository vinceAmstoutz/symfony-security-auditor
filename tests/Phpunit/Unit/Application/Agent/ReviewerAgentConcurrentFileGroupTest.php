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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use Exception;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;

/**
 * Drives the per-file review of findings that share a file through a client
 * that takes several requests at once.
 */
final class ReviewerAgentConcurrentFileGroupTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_calls_of_several_files_are_sent_at_once_when_the_reviewer_runs_concurrently(): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient->expects(self::once())->method('completeBatch')->with(self::countOf(2), 4)->willReturnCallback($this->answerEach(...));

        $reviewed = $this->agent($llmClient)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame(
            [['src/A.php', 1, true], ['src/B.php', 1, false], ['src/A.php', 2, true], ['src/B.php', 2, false]],
            array_map(static fn (Vulnerability $vulnerability): array => [$vulnerability->filePath(), $vulnerability->lineStart(), $vulnerability->isReviewerValidated()], $reviewed),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_structured_calls_of_several_files_are_sent_at_once_when_the_reviewer_runs_concurrently(): void
    {
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient->expects(self::once())->method('completeBatchWithTools')->with(self::countOf(2), 4, ReviewerAgent::DEFAULT_MAX_TOOL_ITERATIONS)->willReturnCallback(
            static fn (array $requests): array => array_map(self::recordEach(...), $requests),
        );

        $reviewed = $this->agent($llmClient, structured: true)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame([true, false, true, false], $this->validatedFlags($reviewed));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_calls_go_out_in_windows_of_at_most_the_concurrency_the_reviewer_allows(): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::once())->method('completeBatch')->with(self::countOf(2), 2)->willReturnCallback($this->answerEach(...));
        $llmClient->expects(self::once())->method('complete')->willReturnCallback(static fn (string $system, string $user): LLMResponse => self::verdicts($user));

        $reviewed = $this->agent($llmClient, maxConcurrent: 2)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php', 'src/C.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame([true, false, false, true, false, false], $this->validatedFlags($reviewed));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_each_call_is_sent_alone_when_the_reviewer_does_not_run_concurrently(): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatch');
        $llmClient->expects(self::exactly(2))->method('complete')->willReturnCallback(static fn (string $system, string $user): LLMResponse => self::verdicts($user));

        $reviewed = $this->agent($llmClient, maxConcurrent: 1)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame([true, false, true, false], $this->validatedFlags($reviewed));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_review_in_batches_of_several_findings_sends_its_calls_one_at_a_time(): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatch');
        $llmClient->expects(self::exactly(2))->method('complete')->willReturnCallback(static fn (string $system, string $user): LLMResponse => self::verdicts($user));

        $reviewed = (new ReviewerAgent(
            new ReviewerAgentCollaborators($llmClient, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(batchSize: 2, maxConcurrent: 4),
        ))->review($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()));

        self::assertCount(4, $reviewed);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_review_that_reads_json_sends_its_calls_without_tools_to_a_client_that_also_takes_tools(): void
    {
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatchWithTools');
        $llmClient->expects(self::once())->method('completeBatch')->willReturnCallback($this->answerEach(...));

        $reviewed = $this->agent($llmClient)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame([true, false, true, false], $this->validatedFlags($reviewed));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_structured_review_sends_each_call_alone_to_a_client_that_takes_no_batch_with_tools(): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatch');
        $llmClient->expects(self::exactly(2))->method('completeWithTools')->willReturnCallback(
            static fn (string $system, string $user, ToolRegistry $toolRegistry): LLMResponse => self::recordEach(['user' => $user, 'tools' => $toolRegistry]),
        );

        $reviewed = $this->agent($llmClient, structured: true)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame([true, false, true, false], $this->validatedFlags($reviewed));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_review_with_tools_sends_each_call_alone(): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('completeBatch');
        $llmClient->expects(self::exactly(2))->method('completeWithTools')->willReturnCallback(static fn (string $system, string $user): LLMResponse => self::verdicts($user));
        $toolRegistryFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolRegistryFactory->method('forProjectFiles')->willReturn(new ToolRegistry([], new NullLogger()));

        $reviewed = (new ReviewerAgent(
            new ReviewerAgentCollaborators($llmClient, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(toolsEnabled: true, maxConcurrent: 4),
            $toolRegistryFactory,
        ))->reviewByFile($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame([true, false, true, false], $this->validatedFlags($reviewed));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('abortCases')]
    public function test_an_abort_of_a_window_marks_its_findings_and_those_after_it_unreached(Exception $exception, string $status): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient->method('completeBatch')->willThrowException($exception);
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $aborted = false;
        try {
            $this->agent($llmClient, maxConcurrent: 2)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php', 'src/C.php'), [], $auditContext, false, null);
        } catch (BudgetExceededException|LLMProviderException) {
            $aborted = true;
        }

        self::assertTrue($aborted, 'The reviewer must rethrow the abort.');
        self::assertSame(
            [['src/A.php', $status], ['src/A.php', $status], ['src/B.php', $status], ['src/B.php', $status], ['src/C.php', $status], ['src/C.php', $status]],
            $this->reviewerCoverage($auditContext),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('abortCases')]
    public function test_an_abort_of_a_structured_window_keeps_the_verdicts_recorded_before_it(Exception $exception, string $status): void
    {
        $findings = $this->findingsIn('src/A.php', 'src/B.php');
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests) use ($findings, $exception): never {
            ReviewerAgentHarness::registryOf($requests[0])->execute('record_review', ['id' => $findings[0]->id(), 'accepted' => true]);

            throw $exception;
        });
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $aborted = false;
        try {
            $this->agent($llmClient, structured: true)->reviewByFile($findings, [], $auditContext, false, null);
        } catch (BudgetExceededException|LLMProviderException) {
            $aborted = true;
        }

        self::assertTrue($aborted, 'The reviewer must rethrow the abort.');
        self::assertSame(
            [['src/A.php', 'validated'], ['src/A.php', $status], ['src/B.php', $status], ['src/B.php', $status]],
            $this->reviewerCoverage($auditContext),
        );
    }

    /** @return iterable<string, array{Exception, string}> */
    public static function abortCases(): iterable
    {
        yield 'budget exceeded' => [BudgetExceededException::forTokens(500, 100), 'aborted'];
        yield 'provider failure' => [new LLMProviderException('platform unreachable'), 'errored'];
    }

    /**
     * @param list<bool> $expectedFlags
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('failedWindowCases')]
    public function test_a_window_whose_call_fails_otherwise_records_its_findings_as_errors_keeping_the_verdicts_recorded_before(bool $structured, array $expectedFlags): void
    {
        $findings = $this->findingsIn('src/A.php', 'src/B.php');
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatch')->willThrowException(new RuntimeException('connection reset'));
        $llmClient->method('completeBatchWithTools')->willReturnCallback(static function (array $requests) use ($findings): never {
            ReviewerAgentHarness::registryOf($requests[0])->execute('record_review', ['id' => $findings[0]->id(), 'accepted' => true]);

            throw new RuntimeException('connection reset');
        });

        $reviewed = $this->agent($llmClient, $structured)->reviewByFile($findings, [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame($expectedFlags, $this->validatedFlags($reviewed));
    }

    /** @return iterable<string, array{bool, list<bool>}> */
    public static function failedWindowCases(): iterable
    {
        yield 'answers read as JSON' => [false, [false, false, false, false]];
        yield 'verdicts recorded through record_review' => [true, [true, false, false, false]];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_batch_of_a_window_the_model_cannot_take_in_whole_is_split_and_each_half_sent_alone(): void
    {
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::once())->method('completeBatch')->willReturnCallback(
            static fn (array $requests): array => [self::tooLarge(), self::verdicts(self::userOf($requests[1] ?? null)), self::tooLarge()],
        );
        $llmClient->expects(self::exactly(4))->method('complete')->willReturnCallback(static fn (string $system, string $user): LLMResponse => self::verdicts($user));

        $reviewed = $this->agent($llmClient)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php', 'src/C.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame(
            [['src/A.php', true], ['src/B.php', false], ['src/C.php', false], ['src/A.php', true], ['src/B.php', false], ['src/C.php', false]],
            array_map(static fn (Vulnerability $vulnerability): array => [$vulnerability->filePath(), $vulnerability->isReviewerValidated()], $reviewed),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('abortCases')]
    public function test_an_abort_while_splitting_a_batch_marks_the_batches_still_to_split_unreached(Exception $exception, string $status): void
    {
        $calls = 0;
        $llmClient = self::createStub(BatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatch')->willReturn([self::tooLarge(), self::tooLarge(), self::tooLarge()]);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$calls, $exception): LLMResponse {
            if (3 === ++$calls) {
                throw $exception;
            }

            return self::verdicts($user, true);
        });
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $aborted = false;
        try {
            $this->agent($llmClient)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php', 'src/C.php'), [], $auditContext, false, null);
        } catch (BudgetExceededException|LLMProviderException) {
            $aborted = true;
        }

        self::assertTrue($aborted, 'The reviewer must rethrow the abort.');
        self::assertSame(
            [['src/A.php', 'validated'], ['src/A.php', 'validated'], ['src/B.php', $status], ['src/B.php', $status], ['src/C.php', $status], ['src/C.php', $status]],
            $this->reviewerCoverage($auditContext),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_failure_to_read_one_answer_of_a_window_records_that_batch_alone_as_an_error(): void
    {
        $llmClient = self::createStub(BatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatch')->willReturnCallback(
            static fn (array $requests): array => array_map(static fn (mixed $request): LLMResponse => self::verdicts(self::userOf($request), true), $requests),
        );
        $progressReporter = new class implements ProgressReporterInterface {
            #[Override]
            public function report(string $event, array $context = []): void
            {
                if (true === ($context['accepted'] ?? null) && 'src/A.php' === ($context['file'] ?? null)) {
                    throw new RuntimeException('progress display closed');
                }
            }
        };

        $reviewed = $this->agent($llmClient, progressReporter: $progressReporter)->reviewByFile($this->findingsIn('src/A.php', 'src/B.php'), [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame([false, true, false, true], $this->validatedFlags($reviewed));
    }

    private function agent(LLMClientInterface $llmClient, bool $structured = false, int $maxConcurrent = 4, ProgressReporterInterface $progressReporter = new NullProgressReporter()): ReviewerAgent
    {
        return new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $llmClient,
                new ReviewerPromptBuilder(useStructuredCollection: $structured),
                new NullLogger(),
                recordReviewToolFactory: $structured ? new RecordReviewToolFactory() : null,
                progressReporter: $progressReporter,
            ),
            new ReviewerModeConfiguration(maxConcurrent: $maxConcurrent, useStructuredCollection: $structured),
        );
    }

    /**
     * Two findings in each file, the files interleaved.
     *
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function findingsIn(string ...$filePaths): array
    {
        $findings = [];
        foreach ([1, 2] as $line) {
            foreach ($filePaths as $filePath) {
                $findings[] = Vulnerability::of(
                    new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, \sprintf('Static analysis at %s:%d', $filePath, $line), 0.8),
                    new CodeLocation($filePath, $line, $line),
                    new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                    'c',
                );
            }
        }

        return $findings;
    }

    /**
     * @param array<mixed> $requests
     *
     * @return list<LLMResponse>
     *
     * @throws InvalidTokenUsageException
     */
    private function answerEach(array $requests): array
    {
        return array_values(array_map(static fn (mixed $request): LLMResponse => self::verdicts(self::userOf($request)), $requests));
    }

    private static function userOf(mixed $request): string
    {
        self::assertIsArray($request);
        self::assertIsString($request['user'] ?? null);

        return $request['user'];
    }

    /**
     * Accepts every finding of `src/A.php` the batch message lists and
     * rejects the others.
     *
     * @throws InvalidTokenUsageException
     */
    private static function verdicts(string $userMessage, ?bool $accepted = null): LLMResponse
    {
        preg_match_all('/^ID: (\S+)$/m', $userMessage, $matches);

        return LLMResponse::of(
            (string) json_encode(array_map(static fn (string $id): array => ['id' => $id, 'accepted' => $accepted ?? str_contains($userMessage, 'src/A.php')], $matches[1])),
            'test',
            'end_turn',
            TokenUsageSnapshot::of(0, 0),
        );
    }

    /**
     * Records through `record_review` a verdict for each finding the batch
     * message lists, accepting those of `src/A.php`.
     *
     * @throws InvalidTokenUsageException
     */
    private static function recordEach(mixed $request): LLMResponse
    {
        $userMessage = self::userOf($request);
        preg_match_all('/^ID: (\S+)$/m', $userMessage, $matches);
        foreach ($matches[1] as $id) {
            ReviewerAgentHarness::registryOf($request)->execute('record_review', ['id' => $id, 'accepted' => str_contains($userMessage, 'src/A.php')]);
        }

        return LLMResponse::of('', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function tooLarge(): LLMResponse
    {
        return LLMResponse::of('prompt is too long', 'test', 'request_too_large', TokenUsageSnapshot::of(0, 0));
    }

    /**
     * @param list<Vulnerability> $reviewed
     *
     * @return list<bool>
     */
    private function validatedFlags(array $reviewed): array
    {
        return array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed);
    }

    /**
     * @return list<array{string, string}>
     */
    private function reviewerCoverage(AuditContext $auditContext): array
    {
        return array_values(array_map(
            static fn (array $entry): array => [$entry['file'], $entry['status']],
            array_filter($auditContext->coverage(), static fn (array $entry): bool => 'reviewer' === $entry['stage']),
        ));
    }
}
