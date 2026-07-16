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
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\StructuredReviewCollectionSession;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ReviewOutcomeRecorderTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_accepted_verdict_reports_the_finding_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(true);

        $vulnerability = $this->recorder($progressReporter)->recordVerdict($this->vulnerability(), ['accepted' => true], new NullCoverageRecorder());

        self::assertTrue($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_rejected_verdict_reports_the_finding_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(false);

        $vulnerability = $this->recorder($progressReporter)->recordVerdict($this->vulnerability(), ['accepted' => false], new NullCoverageRecorder());

        self::assertFalse($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_finding_without_any_verdict_still_reports_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(false);

        $vulnerability = $this->recorder($progressReporter)->recordVerdict($this->vulnerability(), null, new NullCoverageRecorder());

        self::assertFalse($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_errored_review_still_reports_the_finding_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(false);

        $vulnerability = $this->recorder($progressReporter)->recordReviewError($this->vulnerability(), new RuntimeException('llm down'), new NullCoverageRecorder());

        self::assertFalse($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_recover_drained_verdict_returns_null_when_nothing_was_recorded(): void
    {
        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin(new RecordReviewToolFactory(), new NullLogger());

        $result = $this->recorder(self::createStub(ProgressReporterInterface::class))->recoverDrainedVerdict($this->vulnerability(), $structuredReviewCollectionSession, new NullCoverageRecorder());

        self::assertNull($result);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_recover_drained_verdict_applies_the_last_recorded_verdict(): void
    {
        $vulnerability = $this->vulnerability();
        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin(new RecordReviewToolFactory(), new NullLogger());
        $structuredReviewCollectionSession->toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

        $progressReporter = $this->expectingReviewedEvent(true);
        $result = $this->recorder($progressReporter)->recoverDrainedVerdict($vulnerability, $structuredReviewCollectionSession, new NullCoverageRecorder());

        self::assertNotNull($result);
        self::assertTrue($result->isReviewerValidated());
    }

    /**
     * A verdict recovered after a mid-conversation abort was genuinely
     * reached by the reviewer LLM — the same as a normal, non-aborted
     * success — so it must be cached the same way, or a retried run pays for
     * an LLM call that already produced a reliable answer.
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_recover_drained_verdict_caches_the_recovered_verdict_when_a_code_context_is_given(): void
    {
        $vulnerability = $this->vulnerability();
        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin(new RecordReviewToolFactory(), new NullLogger());
        $structuredReviewCollectionSession->toolRegistry->execute('record_review', ['id' => $vulnerability->id(), 'accepted' => true]);

        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::once())->method('store')->with($vulnerability, 'code-context');

        $reviewOutcomeRecorder = new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache($reviewerCache, new NullLogger()),
            new NullLogger(),
            self::createStub(ProgressReporterInterface::class),
        );

        $result = $reviewOutcomeRecorder->recoverDrainedVerdict($vulnerability, $structuredReviewCollectionSession, new NullCoverageRecorder(), 'code-context');

        self::assertNotNull($result);
        self::assertTrue($result->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_apply_response_still_applies_the_verdict_when_the_cache_store_throws(): void
    {
        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('store')->willThrowException(new RuntimeException('disk full'));

        $reviewOutcomeRecorder = new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache($reviewerCache, new NullLogger()),
            new NullLogger(),
            self::createStub(ProgressReporterInterface::class),
        );

        $vulnerability = $reviewOutcomeRecorder->applyResponse(
            $this->vulnerability(),
            LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
            new NullCoverageRecorder(),
            'code-context',
        );

        self::assertTrue($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_null_verdict_records_the_rejected_finding_with_the_coverage_recorder(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerability = $this->recorder(self::createStub(ProgressReporterInterface::class))->recordVerdict($this->vulnerability(), null, $recordingCoverageRecorder);

        self::assertSame([$vulnerability], $recordingCoverageRecorder->reviewed);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_errored_review_records_the_finding_with_the_coverage_recorder(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerability = $this->recorder(self::createStub(ProgressReporterInterface::class))->recordReviewError($this->vulnerability(), new RuntimeException('llm down'), $recordingCoverageRecorder);

        self::assertSame([$vulnerability], $recordingCoverageRecorder->reviewed);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_parse_failure_records_the_errored_finding_with_the_coverage_recorder(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerability = $this->recorder(self::createStub(ProgressReporterInterface::class))->applyResponse(
            $this->vulnerability(),
            LLMResponse::of('not json {{{', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
            $recordingCoverageRecorder,
        );

        self::assertSame([$vulnerability], $recordingCoverageRecorder->reviewed);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_rejected_verdict_with_reviewer_notes_is_recorded_to_triage_memory(): void
    {
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::once())->method('record')->with('sql_injection', 'src/A.php', 'T', 18, 'not exploitable: input is validated upstream');

        $reviewOutcomeRecorder = new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            self::createStub(ProgressReporterInterface::class),
            $triageMemoryRecorder,
        );

        $reviewOutcomeRecorder->recordVerdict(
            $this->vulnerability(),
            ['accepted' => false, 'reviewer_notes' => 'not exploitable: input is validated upstream'],
            new NullCoverageRecorder(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_accepted_verdict_is_not_recorded_to_triage_memory(): void
    {
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::never())->method('record');

        $reviewOutcomeRecorder = new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            self::createStub(ProgressReporterInterface::class),
            $triageMemoryRecorder,
        );

        $reviewOutcomeRecorder->recordVerdict(
            $this->vulnerability(),
            ['accepted' => true, 'reviewer_notes' => 'confirmed exploitable'],
            new NullCoverageRecorder(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_rejected_verdict_without_reviewer_notes_is_not_recorded_to_triage_memory(): void
    {
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::never())->method('record');

        $reviewOutcomeRecorder = new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            self::createStub(ProgressReporterInterface::class),
            $triageMemoryRecorder,
        );

        $reviewOutcomeRecorder->recordVerdict(
            $this->vulnerability(),
            ['accepted' => false],
            new NullCoverageRecorder(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_rejected_verdict_with_whitespace_only_reviewer_notes_is_not_recorded_to_triage_memory(): void
    {
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::never())->method('record');

        $reviewOutcomeRecorder = new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            self::createStub(ProgressReporterInterface::class),
            $triageMemoryRecorder,
        );

        $reviewOutcomeRecorder->recordVerdict(
            $this->vulnerability(),
            ['accepted' => false, 'reviewer_notes' => '   '],
            new NullCoverageRecorder(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_finding_without_any_verdict_is_not_recorded_to_triage_memory(): void
    {
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::never())->method('record');

        $reviewOutcomeRecorder = new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            self::createStub(ProgressReporterInterface::class),
            $triageMemoryRecorder,
        );

        $reviewOutcomeRecorder->recordVerdict($this->vulnerability(), null, new NullCoverageRecorder());
    }

    private function expectingReviewedEvent(bool $accepted): ProgressReporterInterface
    {
        $progressReporter = $this->createMock(ProgressReporterInterface::class);
        $progressReporter->expects(self::once())->method('report')->with(
            'review.finding.reviewed',
            ['accepted' => $accepted, 'type' => 'sql_injection', 'file' => 'src/A.php', 'line' => 18],
        );

        return $progressReporter;
    }

    private function recorder(ProgressReporterInterface $progressReporter): ReviewOutcomeRecorder
    {
        return new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            $progressReporter,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerability(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'T', 0.9),
            new CodeLocation('src/A.php', 18, 20),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
