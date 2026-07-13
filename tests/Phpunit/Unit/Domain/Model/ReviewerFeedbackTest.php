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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;

final class ReviewerFeedbackTest extends TestCase
{
    public function test_none_is_empty(): void
    {
        self::assertTrue(ReviewerFeedback::none()->isEmpty());
    }

    public function test_feedback_with_entries_is_not_empty(): void
    {
        self::assertFalse($this->feedback('accepted risk')->isEmpty());
    }

    public function test_empty_feedback_digests_to_the_empty_string(): void
    {
        self::assertSame('', ReviewerFeedback::none()->digest());
    }

    public function test_the_digest_is_stable_for_equal_feedback(): void
    {
        self::assertSame($this->feedback('accepted risk')->digest(), $this->feedback('accepted risk')->digest());
    }

    public function test_the_digest_changes_when_a_reason_changes(): void
    {
        self::assertNotSame($this->feedback('accepted risk')->digest(), $this->feedback('guarded by voter')->digest());
    }

    public function test_the_digest_separates_fields_so_shifted_values_do_not_collide(): void
    {
        $reviewerFeedback = new ReviewerFeedback([new AcceptedFindingFeedback('sql_injection', 'src/A.phpTitle', '', 'accepted risk')]);

        self::assertNotSame($this->feedback('accepted risk')->digest(), $reviewerFeedback->digest());
    }

    private function feedback(string $reason): ReviewerFeedback
    {
        return new ReviewerFeedback([new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', $reason)]);
    }
}
