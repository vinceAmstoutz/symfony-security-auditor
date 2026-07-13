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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;

final class ReviewerFeedbackHolderTest extends TestCase
{
    public function test_it_carries_no_feedback_before_set_is_called(): void
    {
        self::assertTrue((new ReviewerFeedbackHolder())->feedback()->isEmpty());
    }

    public function test_it_returns_the_feedback_set_on_it(): void
    {
        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $reviewerFeedback = new ReviewerFeedback([new AcceptedFindingFeedback('sql_injection', 'src/A.php', 'Title', 'accepted risk')]);

        $reviewerFeedbackHolder->set($reviewerFeedback);

        self::assertSame($reviewerFeedback, $reviewerFeedbackHolder->feedback());
    }
}
