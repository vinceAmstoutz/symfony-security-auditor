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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchVerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullTriageMemoryRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class BatchVerdictApplierTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_matches_a_bare_single_review_object_for_a_size_one_batch(): void
    {
        $vulnerability = $this->vulnerability();

        $reviewed = $this->applier()->applyBatchReview(
            [$vulnerability],
            ['id' => $vulnerability->id(), 'accepted' => true],
            new NullCoverageRecorder(),
        );

        self::assertCount(1, $reviewed);
        self::assertTrue($reviewed[0]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_matches_a_list_of_review_objects_by_id(): void
    {
        $vulnerability = $this->vulnerability(lineStart: 18);
        $second = $this->vulnerability(lineStart: 40);

        $reviewed = $this->applier()->applyBatchReview(
            [$vulnerability, $second],
            [
                ['id' => $second->id(), 'accepted' => true],
                ['id' => $vulnerability->id(), 'accepted' => false],
            ],
            new NullCoverageRecorder(),
        );

        self::assertFalse($reviewed[0]->isReviewerValidated());
        self::assertTrue($reviewed[1]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_batch_finding_the_model_gave_no_verdict_for_is_not_cached(): void
    {
        $vulnerability = $this->vulnerability(lineStart: 18);
        $unjudged = $this->vulnerability(lineStart: 40);
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::once())
            ->method('store')
            ->with($vulnerability, 'judged context', ['id' => $vulnerability->id(), 'accepted' => true]);

        $reviewed = $this->applier($reviewerCache)->applyBatchReview(
            [$vulnerability, $unjudged],
            [['id' => $vulnerability->id(), 'accepted' => true]],
            new NullCoverageRecorder(),
            [$vulnerability->id() => 'judged context', $unjudged->id() => 'unjudged context'],
        );

        self::assertTrue($reviewed[0]->isReviewerValidated());
        self::assertFalse($reviewed[1]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_batch_finding_the_model_gave_no_verdict_for_is_recorded_errored_and_not_reported_as_rejected(): void
    {
        $vulnerability = $this->vulnerability(lineStart: 18);
        $unjudged = $this->vulnerability(lineStart: 40);
        $recordingCoverageRecorder = $this->recordingCoverageRecorder();

        $reviewed = $this->applier()->applyBatchReview([$vulnerability, $unjudged], [['id' => $vulnerability->id(), 'accepted' => true]], $recordingCoverageRecorder);

        self::assertSame(['validated', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
        self::assertSame([], $recordingCoverageRecorder->rejected);
        self::assertSame($reviewed, $recordingCoverageRecorder->reviewed);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_empty_answer_records_every_batch_finding_errored_instead_of_matching_scalar_values(): void
    {
        $recordingCoverageRecorder = $this->recordingCoverageRecorder();

        $reviewed = $this->applier()->applyBatchReview([$this->vulnerability(), $this->vulnerability(lineStart: 40)], [], $recordingCoverageRecorder);

        self::assertSame(['errored', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
        self::assertFalse($reviewed[0]->isReviewerValidated());
        self::assertFalse($reviewed[1]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_warning_for_a_finding_without_a_verdict_names_the_finding(): void
    {
        $vulnerability = $this->vulnerability();
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Reviewer batch answer held no verdict for the finding; it is recorded as errored and left out of the cache',
            ['vulnerability_id' => $vulnerability->id()],
        );
        $batchVerdictApplier = new BatchVerdictApplier(new VerdictApplier(new NullLogger()), new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()), $logger, new NullProgressReporter());

        $reviewed = $batchVerdictApplier->applyBatchReview([$vulnerability], [], new NullCoverageRecorder());

        self::assertFalse($reviewed[0]->isReviewerValidated());
    }

    /**
     * @param array<string, mixed> $verdictWithoutAcceptedFlag
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('verdictsWithoutAnAcceptedFlag')]
    public function test_a_batch_verdict_without_an_accepted_flag_is_recorded_errored_and_not_cached(array $verdictWithoutAcceptedFlag): void
    {
        $vulnerability = $this->vulnerability();
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::never())->method('store');
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::never())->method('record');
        $recordingCoverageRecorder = $this->recordingCoverageRecorder();

        $reviewed = $this->applier($reviewerCache, $triageMemoryRecorder)->applyBatchReview(
            [$vulnerability],
            [['id' => $vulnerability->id(), ...$verdictWithoutAcceptedFlag]],
            $recordingCoverageRecorder,
            [$vulnerability->id() => 'context'],
        );

        self::assertFalse($reviewed[0]->isReviewerValidated());
        self::assertSame(['errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
        self::assertSame([], $recordingCoverageRecorder->rejected);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function verdictsWithoutAnAcceptedFlag(): iterable
    {
        yield 'only notes' => [['reviewer_notes' => 'not exploitable']];
        yield 'an adjusted severity alone' => [['adjusted_severity' => 'low']];
        yield 'an accepted flag set to null' => [['accepted' => null]];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_empty_answer_records_the_whole_batch_errored_and_warns_with_the_batch_size(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Reviewer batch answer was empty; its findings are recorded as errored and left out of the cache',
            ['batch_size' => 2],
        );
        $batchVerdictApplier = new BatchVerdictApplier(new VerdictApplier(new NullLogger()), new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()), $logger, new NullProgressReporter());
        $recordingCoverageRecorder = $this->recordingCoverageRecorder();

        $errored = $batchVerdictApplier->recordEmptyAnswer([$this->vulnerability(), $this->vulnerability(lineStart: 40)], $recordingCoverageRecorder);

        self::assertFalse($errored[0]->isReviewerValidated());
        self::assertFalse($errored[1]->isReviewerValidated());
        self::assertSame(['errored', 'errored'], array_column($recordingCoverageRecorder->coverage, 'status'));
        self::assertSame($errored, $recordingCoverageRecorder->reviewed);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_mark_batch_errored_marks_every_finding_as_not_validated(): void
    {
        $errored = $this->applier()->markBatchErrored([$this->vulnerability()], new NullCoverageRecorder());

        self::assertFalse($errored[0]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_record_batch_error_logs_and_marks_every_finding_as_not_validated(): void
    {
        $errored = $this->applier()->recordBatchError([$this->vulnerability()], new RuntimeException('LLM call failed'), new NullCoverageRecorder());

        self::assertFalse($errored[0]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_rejected_fresh_batch_verdict_with_reviewer_notes_is_recorded_to_triage_memory(): void
    {
        $vulnerability = $this->vulnerability(title: 'T');
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::once())->method('record')->with('sql_injection', 'src/A.php', 'T', 18, 'not exploitable: input is validated upstream');

        $this->applier(triageMemoryRecorder: $triageMemoryRecorder)->applyBatchReview(
            [$vulnerability],
            [['id' => $vulnerability->id(), 'accepted' => false, 'reviewer_notes' => 'not exploitable: input is validated upstream']],
            new NullCoverageRecorder(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_accepted_fresh_batch_verdict_is_not_recorded_to_triage_memory(): void
    {
        $vulnerability = $this->vulnerability();
        $triageMemoryRecorder = $this->createMock(TriageMemoryRecorderInterface::class);
        $triageMemoryRecorder->expects(self::never())->method('record');

        $this->applier(triageMemoryRecorder: $triageMemoryRecorder)->applyBatchReview(
            [$vulnerability],
            [['id' => $vulnerability->id(), 'accepted' => true, 'reviewer_notes' => 'confirmed exploitable']],
            new NullCoverageRecorder(),
        );
    }

    private function recordingCoverageRecorder(): RecordingCoverageRecorder
    {
        return new RecordingCoverageRecorder();
    }

    private function applier(?ReviewerCacheInterface $reviewerCache = null, ?TriageMemoryRecorderInterface $triageMemoryRecorder = null): BatchVerdictApplier
    {
        return new BatchVerdictApplier(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache($reviewerCache ?? new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            new NullProgressReporter(),
            $triageMemoryRecorder ?? new NullTriageMemoryRecorder(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerability(string $title = 'v', int $lineStart = 18): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, $title, 0.9),
            new CodeLocation('src/A.php', $lineStart, $lineStart + 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
