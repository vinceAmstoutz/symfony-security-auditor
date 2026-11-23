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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;

/**
 * The feedback `AuditCommand` loads from the run's baseline, none until it
 * sets it.
 *
 * Not readonly: the feedback is set after construction (see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class ReviewerFeedbackHolder implements ReviewerFeedbackProviderInterface
{
    private ReviewerFeedback $reviewerFeedback;

    public function __construct()
    {
        $this->reviewerFeedback = ReviewerFeedback::none();
    }

    public function set(ReviewerFeedback $reviewerFeedback): void
    {
        $this->reviewerFeedback = $reviewerFeedback;
    }

    #[Override]
    public function feedback(): ReviewerFeedback
    {
        return $this->reviewerFeedback;
    }
}
