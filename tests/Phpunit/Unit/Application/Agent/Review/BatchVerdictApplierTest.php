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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;

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
    public function test_a_finding_with_no_matching_verdict_is_rejected(): void
    {
        $vulnerability = $this->vulnerability();

        $reviewed = $this->applier()->applyBatchReview(
            [$vulnerability],
            [['id' => 'VULN-does-not-match', 'accepted' => true]],
            new NullCoverageRecorder(),
        );

        self::assertFalse($reviewed[0]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_empty_response_rejects_every_finding_without_matching_scalar_values(): void
    {
        $vulnerability = $this->vulnerability();

        $reviewed = $this->applier()->applyBatchReview([$vulnerability], [], new NullCoverageRecorder());

        self::assertFalse($reviewed[0]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_reject_batch_marks_every_finding_as_not_validated(): void
    {
        $rejected = $this->applier()->rejectBatch([$this->vulnerability(), $this->vulnerability(title: 'second')], new NullCoverageRecorder());

        self::assertFalse($rejected[0]->isReviewerValidated());
        self::assertFalse($rejected[1]->isReviewerValidated());
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
    public function test_a_finding_with_no_matching_verdict_caches_the_implicit_rejection(): void
    {
        $vulnerability = $this->vulnerability();
        $reviewerCache = $this->createMock(ReviewerCacheInterface::class);
        $reviewerCache->expects(self::once())
            ->method('store')
            ->with($vulnerability, 'context', ['accepted' => false]);

        $this->applier($reviewerCache)->applyBatchReview(
            [$vulnerability],
            [['id' => 'VULN-does-not-match', 'accepted' => true]],
            new NullCoverageRecorder(),
            [$vulnerability->id() => 'context'],
        );
    }

    private function applier(?ReviewerCacheInterface $reviewerCache = null): BatchVerdictApplier
    {
        return new BatchVerdictApplier(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache($reviewerCache ?? new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            new NullProgressReporter(),
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
