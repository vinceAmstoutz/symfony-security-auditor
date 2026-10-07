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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentStructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\SequentialReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\StructuredReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingReviewerCache;

final class ReviewerOmittedVerdictTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('jsonAnswersWithoutAVerdict')]
    public function test_the_sequential_json_review_records_a_finding_the_model_never_judged_errored_not_rejected_and_not_cached(string $content): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of($content, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $recordingReviewerCache = new RecordingReviewerCache();
        $reviewerVerdictCache = new ReviewerVerdictCache($recordingReviewerCache, new NullLogger());
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = (new SequentialReviewAnalyzer($llmClient, new ReviewerPromptBuilder(), $reviewerVerdictCache, $this->reviewOutcomeRecorder($reviewerVerdictCache), 4))
            ->analyze([$this->vulnerabilityAt('src/A.php')], [], $recordingCoverageRecorder, null, false);

        $this->assertErroredNotRejected($reviewed, $recordingCoverageRecorder, $recordingReviewerCache);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function jsonAnswersWithoutAVerdict(): iterable
    {
        yield 'an empty answer' => [''];
        yield 'an empty object' => ['{}'];
        yield 'notes without an accepted flag' => ['{"reviewer_notes": "looks fine"}'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('jsonAnswersWithoutAVerdict')]
    public function test_the_concurrent_json_review_records_a_finding_the_model_never_judged_errored_not_rejected_and_not_cached(string $content): void
    {
        $llmClient = self::createStub(BatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatch')->willReturnCallback(
            static fn (array $requests): array => array_map(static fn (): LLMResponse => LLMResponse::of($content, 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)), $requests),
        );
        $recordingReviewerCache = new RecordingReviewerCache();
        $reviewerVerdictCache = new ReviewerVerdictCache($recordingReviewerCache, new NullLogger());
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = (new ConcurrentReviewAnalyzer($llmClient, new ReviewerPromptBuilder(), $reviewerVerdictCache, $this->reviewOutcomeRecorder($reviewerVerdictCache), 4))
            ->analyze([$this->vulnerabilityAt('src/A.php')], [], $recordingCoverageRecorder, false);

        $this->assertErroredNotRejected($reviewed, $recordingCoverageRecorder, $recordingReviewerCache);
    }

    /**
     * @param array<string, mixed>|null $recordedWithoutVerdict
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('toolCallsWithoutAVerdict')]
    public function test_the_structured_review_records_a_finding_the_model_never_judged_errored_not_rejected_and_not_cached(?array $recordedWithoutVerdict): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(
            static function (string $system, string $user, ToolRegistry $toolRegistry) use ($recordedWithoutVerdict, $vulnerability): LLMResponse {
                if (null !== $recordedWithoutVerdict) {
                    $toolRegistry->execute('record_review', ['id' => $vulnerability->id(), ...$recordedWithoutVerdict]);
                }

                return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
            },
        );
        $recordingReviewerCache = new RecordingReviewerCache();
        $reviewerVerdictCache = new ReviewerVerdictCache($recordingReviewerCache, new NullLogger());
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = (new StructuredReviewAnalyzer($llmClient, new ReviewerPromptBuilder(useStructuredCollection: true), $reviewerVerdictCache, $this->reviewOutcomeRecorder($reviewerVerdictCache), new RecordReviewToolFactory(), new NullLogger(), 4))
            ->analyze([$vulnerability], [], $recordingCoverageRecorder, false);

        $this->assertErroredNotRejected($reviewed, $recordingCoverageRecorder, $recordingReviewerCache);
    }

    /**
     * @param array<string, mixed>|null $recordedWithoutVerdict
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('toolCallsWithoutAVerdict')]
    public function test_the_concurrent_structured_review_records_a_finding_the_model_never_judged_errored_not_rejected_and_not_cached(?array $recordedWithoutVerdict): void
    {
        $vulnerability = $this->vulnerabilityAt('src/A.php');
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(
            static function (array $requests) use ($recordedWithoutVerdict, $vulnerability): array {
                if (null !== $recordedWithoutVerdict) {
                    self::registryOf($requests[0])->execute('record_review', ['id' => $vulnerability->id(), ...$recordedWithoutVerdict]);
                }

                return [LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1))];
            },
        );
        $recordingReviewerCache = new RecordingReviewerCache();
        $reviewerVerdictCache = new ReviewerVerdictCache($recordingReviewerCache, new NullLogger());
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = (new ConcurrentStructuredReviewAnalyzer($llmClient, new ReviewerPromptBuilder(useStructuredCollection: true), $reviewerVerdictCache, $this->reviewOutcomeRecorder($reviewerVerdictCache), new RecordReviewToolFactory(), new NullLogger(), 4, 4))
            ->analyze([$vulnerability], [], $recordingCoverageRecorder, false);

        $this->assertErroredNotRejected($reviewed, $recordingCoverageRecorder, $recordingReviewerCache);
    }

    /**
     * @return iterable<string, array{array<string, mixed>|null}>
     */
    public static function toolCallsWithoutAVerdict(): iterable
    {
        yield 'no record_review call' => [null];
        yield 'a record_review call without an accepted flag' => [['reviewer_notes' => 'looks fine']];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidTokenUsageException
     */
    public function test_an_explicit_rejection_is_still_a_rejection_reported_to_the_attacker_and_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('{"accepted": false}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $recordingReviewerCache = new RecordingReviewerCache();
        $reviewerVerdictCache = new ReviewerVerdictCache($recordingReviewerCache, new NullLogger());
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = (new SequentialReviewAnalyzer($llmClient, new ReviewerPromptBuilder(), $reviewerVerdictCache, $this->reviewOutcomeRecorder($reviewerVerdictCache), 4))
            ->analyze([$this->vulnerabilityAt('src/A.php')], [], $recordingCoverageRecorder, null, false);

        self::assertFalse($reviewed[0]->isReviewerValidated());
        self::assertSame(['rejected'], array_column($recordingCoverageRecorder->coverage, 'status'));
        self::assertSame($reviewed, $recordingCoverageRecorder->rejected);
        self::assertSame([['accepted' => false]], $recordingReviewerCache->stored);
    }

    /**
     * @param list<Vulnerability> $reviewed
     */
    private function assertErroredNotRejected(array $reviewed, RecordingCoverageRecorder $recordingCoverageRecorder, RecordingReviewerCache $recordingReviewerCache): void
    {
        self::assertFalse($reviewed[0]->isReviewerValidated());
        self::assertSame([['stage' => 'reviewer', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
        self::assertSame([], $recordingCoverageRecorder->rejected);
        self::assertSame([], $recordingReviewerCache->stored);
    }

    private static function registryOf(mixed $request): ToolRegistry
    {
        self::assertIsArray($request);
        $toolRegistry = $request['tools'] ?? null;
        self::assertInstanceOf(ToolRegistry::class, $toolRegistry);

        return $toolRegistry;
    }

    private function reviewOutcomeRecorder(ReviewerVerdictCache $reviewerVerdictCache): ReviewOutcomeRecorder
    {
        return new ReviewOutcomeRecorder(new VerdictApplier(new NullLogger()), $reviewerVerdictCache, new NullLogger(), new NullProgressReporter());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerabilityAt(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::HIGH, 'Test '.$filePath, 0.9),
            new CodeLocation($filePath, 1, 5),
            new VulnerabilityNarrative('Test', 'vec', 'proof', 'fix'),
            'code',
        );
    }
}
