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

    public function test_the_digest_is_independent_of_entry_order(): void
    {
        $first = new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Alpha', 'guarded by voter');
        $second = new AcceptedFindingFeedback('xss', 'src/B.php', 'Beta', 'output escaped');

        self::assertSame(
            (new ReviewerFeedback([$first, $second]))->digest(),
            (new ReviewerFeedback([$second, $first]))->digest(),
        );
    }

    public function test_the_digest_does_not_collide_when_one_reason_embeds_another_entrys_whole_line(): void
    {
        $separateEntries = new ReviewerFeedback([
            new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', 'X'),
            new AcceptedFindingFeedback('sql_injection', 'src/B.php', 'TitleB', 'Y'),
        ]);
        $singleEntryEmbeddingTheOthersBoundary = new ReviewerFeedback([
            new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', "Xsql_injection\0src/B.php\0TitleB\0Y"),
        ]);

        self::assertNotSame($separateEntries->digest(), $singleEntryEmbeddingTheOthersBoundary->digest());
    }

    public function test_the_digest_changes_when_the_type_changes(): void
    {
        $sqlInjection = new ReviewerFeedback([new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', 'accepted risk')]);
        $xss = new ReviewerFeedback([new AcceptedFindingFeedback('xss', 'src/A.php', 'Title', 'accepted risk')]);

        self::assertNotSame($sqlInjection->digest(), $xss->digest());
    }

    public function test_the_digest_does_not_collide_when_a_nul_byte_shifts_a_value_across_the_file_and_title_boundary(): void
    {
        $fileEndsWithNulTitle = new ReviewerFeedback([
            new AcceptedFindingFeedback('sql_injection', "src/A.php\0EvilTitle", 'reason-x', 'r'),
        ]);
        $titleStartsAfterTheSameNul = new ReviewerFeedback([
            new AcceptedFindingFeedback('sql_injection', 'src/A.php', "EvilTitle\0reason-x", 'r'),
        ]);

        self::assertNotSame($fileEndsWithNulTitle->digest(), $titleStartsAfterTheSameNul->digest());
    }

    private function feedback(string $reason): ReviewerFeedback
    {
        return new ReviewerFeedback([new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', $reason)]);
    }
}
