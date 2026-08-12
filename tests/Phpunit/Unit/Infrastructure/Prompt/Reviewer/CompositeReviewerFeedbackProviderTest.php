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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt\Reviewer;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullReviewerFeedbackProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\CompositeReviewerFeedbackProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;

final class CompositeReviewerFeedbackProviderTest extends TestCase
{
    public function test_feedback_is_empty_when_both_sources_are_empty(): void
    {
        $compositeReviewerFeedbackProvider = new CompositeReviewerFeedbackProvider(new NullReviewerFeedbackProvider(), new NullReviewerFeedbackProvider());

        self::assertTrue($compositeReviewerFeedbackProvider->feedback()->isEmpty());
    }

    public function test_feedback_merges_entries_from_both_sources(): void
    {
        $baselineEntry = new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'A', 'baseline reason');
        $triageMemoryEntry = new AcceptedFindingFeedback('xxe', 'src/B.php', 'B', 'triage memory reason');

        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $reviewerFeedbackHolder->set(new ReviewerFeedback([$baselineEntry]));

        $triageMemoryProvider = self::createStub(ReviewerFeedbackProviderInterface::class);
        $triageMemoryProvider->method('feedback')->willReturn(new ReviewerFeedback([$triageMemoryEntry]));

        $compositeReviewerFeedbackProvider = new CompositeReviewerFeedbackProvider($reviewerFeedbackHolder, $triageMemoryProvider);

        self::assertEquals([$baselineEntry, $triageMemoryEntry], $compositeReviewerFeedbackProvider->feedback()->entries);
    }

    public function test_feedback_deduplicates_by_finding_identity_keeping_the_primary_entry(): void
    {
        $baselineA = new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'A', 'baseline reason');
        $baselineB = new AcceptedFindingFeedback('xxe', 'src/B.php', 'B', 'baseline B');
        $triageA = new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'A', 'triage-memory reason');
        $triageC = new AcceptedFindingFeedback('csrf', 'src/C.php', 'C', 'triage C');

        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $reviewerFeedbackHolder->set(new ReviewerFeedback([$baselineA, $baselineB]));

        $triageMemoryProvider = self::createStub(ReviewerFeedbackProviderInterface::class);
        $triageMemoryProvider->method('feedback')->willReturn(new ReviewerFeedback([$triageA, $triageC]));

        $compositeReviewerFeedbackProvider = new CompositeReviewerFeedbackProvider($reviewerFeedbackHolder, $triageMemoryProvider);

        self::assertEquals([$baselineA, $baselineB, $triageC], $compositeReviewerFeedbackProvider->feedback()->entries);
    }

    public function test_feedback_does_not_deduplicate_findings_that_share_a_file_and_title_but_differ_in_type(): void
    {
        $sqlInjection = new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', 'sql injection reason');
        $xss = new AcceptedFindingFeedback('xss', 'src/A.php', 'Title', 'xss reason');

        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $reviewerFeedbackHolder->set(new ReviewerFeedback([$sqlInjection]));

        $triageMemoryProvider = self::createStub(ReviewerFeedbackProviderInterface::class);
        $triageMemoryProvider->method('feedback')->willReturn(new ReviewerFeedback([$xss]));

        $compositeReviewerFeedbackProvider = new CompositeReviewerFeedbackProvider($reviewerFeedbackHolder, $triageMemoryProvider);

        self::assertEquals([$sqlInjection, $xss], $compositeReviewerFeedbackProvider->feedback()->entries);
    }

    public function test_feedback_does_not_deduplicate_distinct_findings_whose_file_and_title_share_a_nul_boundary(): void
    {
        $baselineEntry = new AcceptedFindingFeedback('sql_injection', "src/A.php\0Evil", 'Title', 'baseline reason');
        $triageMemoryEntry = new AcceptedFindingFeedback('sql_injection', 'src/A.php', "Evil\0Title", 'triage-memory reason');

        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $reviewerFeedbackHolder->set(new ReviewerFeedback([$baselineEntry]));

        $triageMemoryProvider = self::createStub(ReviewerFeedbackProviderInterface::class);
        $triageMemoryProvider->method('feedback')->willReturn(new ReviewerFeedback([$triageMemoryEntry]));

        $compositeReviewerFeedbackProvider = new CompositeReviewerFeedbackProvider($reviewerFeedbackHolder, $triageMemoryProvider);

        self::assertEquals([$baselineEntry, $triageMemoryEntry], $compositeReviewerFeedbackProvider->feedback()->entries);
    }

    public function test_feedback_is_snapshotted_on_first_read_and_ignores_later_secondary_writes(): void
    {
        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $compositeReviewerFeedbackProvider = new CompositeReviewerFeedbackProvider(new NullReviewerFeedbackProvider(), $reviewerFeedbackHolder);

        $reviewerFeedback = $compositeReviewerFeedbackProvider->feedback();
        $reviewerFeedbackHolder->set(new ReviewerFeedback([new AcceptedFindingFeedback('xxe', 'src/B.php', 'B', 'recorded mid-run')]));

        self::assertSame($reviewerFeedback, $compositeReviewerFeedbackProvider->feedback());
        self::assertTrue($compositeReviewerFeedbackProvider->feedback()->isEmpty());
    }

    public function test_resetting_for_a_new_run_picks_up_secondary_writes_recorded_during_the_previous_run(): void
    {
        $acceptedFindingFeedback = new AcceptedFindingFeedback('xxe', 'src/B.php', 'B', 'recorded during the previous run');
        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $compositeReviewerFeedbackProvider = new CompositeReviewerFeedbackProvider(new NullReviewerFeedbackProvider(), $reviewerFeedbackHolder);

        self::assertTrue($compositeReviewerFeedbackProvider->feedback()->isEmpty());

        $reviewerFeedbackHolder->set(new ReviewerFeedback([$acceptedFindingFeedback]));
        $compositeReviewerFeedbackProvider->resetForNewRun();

        self::assertEquals([$acceptedFindingFeedback], $compositeReviewerFeedbackProvider->feedback()->entries);
    }
}
