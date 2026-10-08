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

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchVerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewBatchSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class BatchReviewAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_structured_batch_marks_every_finding_errored_exactly_once_before_rethrowing_a_provider_failure(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willThrowException(new LLMProviderException('platform gone'));

        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $providerFailed = false;
        try {
            $this->analyzer($llmClient)->analyze(
                [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')],
                [],
                new ReviewBatchSettings(5, true, false, $recordingCoverageRecorder, null),
            );
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The analyzer must rethrow LLMProviderException.');
        self::assertSame(
            [
                ['stage' => 'reviewer', 'filePath' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'filePath' => 'src/B.php', 'status' => 'errored'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    private function analyzer(LLMClientInterface $llmClient, ?ReviewerCacheInterface $reviewerCache = null, ?LoggerInterface $logger = null, ?LoggerInterface $applierLogger = null): BatchReviewAnalyzer
    {
        $verdictApplier = new VerdictApplier(new NullLogger());
        $reviewerVerdictCache = new ReviewerVerdictCache($reviewerCache ?? new NullReviewerCache(), new NullLogger());

        return new BatchReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new BatchVerdictApplier($verdictApplier, $reviewerVerdictCache, $applierLogger ?? new NullLogger(), new NullProgressReporter()),
            $reviewerVerdictCache,
            new ReviewOutcomeRecorder($verdictApplier, $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            $logger ?? new NullLogger(),
            4,
            new RecordReviewToolFactory(),
        );
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

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_json_batch_cut_by_the_token_limit_applies_the_verdict_it_reached_and_records_the_rest_as_errored(): void
    {
        [$first, $second, $third] = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php'), $this->vulnerabilityAt('src/C.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of(
            \sprintf('[{"id": "%s", "accepted": true}, {"id": "%s", "accepted": tr', $first->id(), $second->id()),
            'm',
            'length',
            TokenUsageSnapshot::of(1, 1),
        ));
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())->method('store')->with($first, self::anything(), self::anything());
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Reviewer batch response was cut short; the findings it never reached are recorded as errored',
            ['batch_size' => 3, 'stop_reason' => 'length', 'verdicts_kept' => 1],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient, $reviewerCache, $logger)->analyze([$first, $second, $third], [], new ReviewBatchSettings(3, false, false, $recordingCoverageRecorder, null));

        self::assertSame([true, false, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'errored', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_batch_stopped_at_the_tool_cap_records_the_members_it_never_reached_as_errored_not_rejected(): void
    {
        [$first, $second] = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($first): LLMResponse {
            $toolRegistry->execute('record_review', ['id' => $first->id(), 'accepted' => false]);

            return LLMResponse::of('', 'm', 'max_tool_iterations', TokenUsageSnapshot::of(1, 1));
        });
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())->method('store')->with($first, self::anything(), self::anything());
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Reviewer batch response was cut short; the findings it never reached are recorded as errored',
            ['batch_size' => 2, 'stop_reason' => 'max_tool_iterations', 'verdicts_kept' => 1],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $this->analyzer($llmClient, $reviewerCache, $logger)->analyze([$first, $second], [], new ReviewBatchSettings(5, true, false, $recordingCoverageRecorder, null));

        self::assertSame(['rejected', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_an_empty_json_batch_answer_that_was_cut_short_marks_the_whole_batch_errored_not_rejected(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('', 'm', 'empty_content', TokenUsageSnapshot::of(1, 1)));
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient, $reviewerCache)->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], new ReviewBatchSettings(5, false, false, $recordingCoverageRecorder, null));

        self::assertSame([false, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['errored', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_an_empty_json_batch_answer_that_ended_normally_marks_the_whole_batch_errored_not_rejected_and_not_cached(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::never())->method('store');
        $applierLogger = $this->createMock(LoggerInterface::class);
        $applierLogger->expects(self::once())->method('warning')->with('Reviewer batch answer was empty; its findings are recorded as errored and left out of the cache', ['batch_size' => 2]);
        $applierLogger->expects(self::never())->method('error');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient, $reviewerCache, null, $applierLogger)->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], new ReviewBatchSettings(5, false, false, $recordingCoverageRecorder, null));

        self::assertSame([false, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['errored', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
        self::assertSame([], $recordingCoverageRecorder->rejected);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_batch_that_ended_normally_without_a_verdict_for_every_member_records_the_others_errored_not_rejected_and_not_cached(): void
    {
        [$first, $second] = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($first): LLMResponse {
            $toolRegistry->execute('record_review', ['id' => $first->id(), 'accepted' => true]);

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(null);
        $reviewerCache->expects(self::once())->method('store')->with($first, self::anything(), self::anything());
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient, $reviewerCache, $logger)->analyze([$first, $second], [], new ReviewBatchSettings(5, true, false, $recordingCoverageRecorder, null));

        self::assertSame([true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
        self::assertSame([], $recordingCoverageRecorder->rejected);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_json_batch_the_model_cannot_fit_is_split_and_a_lone_finding_that_still_does_not_fit_is_errored(): void
    {
        $findings = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php'), $this->vulnerabilityAt('src/C.php')];
        $ids = array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->id(), $findings);
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use ($ids): LLMResponse {
            $inPrompt = array_values(array_filter($ids, static fn (string $id): bool => str_contains($user, $id)));
            if (3 === \count($inPrompt) || [$ids[2]] === $inPrompt) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return LLMResponse::of(json_encode(array_map(static fn (string $id): array => ['id' => $id, 'accepted' => true], $inPrompt), \JSON_THROW_ON_ERROR), 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient)->analyze($findings, [], new ReviewBatchSettings(3, false, false, $recordingCoverageRecorder, null));

        self::assertSame([true, true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'validated', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_structured_batch_the_model_cannot_fit_is_split_and_each_half_records_its_verdicts(): void
    {
        $findings = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')];
        $ids = array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->id(), $findings);
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('completeWithTools')->willReturnCallback(static function (string $system, string $user, ToolRegistry $toolRegistry) use ($ids): LLMResponse {
            $inPrompt = array_values(array_filter($ids, static fn (string $id): bool => str_contains($user, $id)));
            if (2 === \count($inPrompt)) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            $reviewedId = current($inPrompt);
            $toolRegistry->execute('record_review', ['id' => $reviewedId, 'accepted' => $ids[0] === $reviewedId]);

            return LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $reviewed = $this->analyzer($llmClient)->analyze($findings, [], new ReviewBatchSettings(5, true, false, $recordingCoverageRecorder, null));

        self::assertSame([true, false], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
        self::assertSame(['validated', 'rejected'], array_column($recordingCoverageRecorder->coverage, 'status'));
    }
}
