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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Feedback;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;

/**
 * Mutable delegate wiring the `ReviewerFeedbackProviderInterface` seam between
 * container construction and command invocation. The reviewer prompt builder and
 * cache receive this holder; `AuditCommand` calls `set()` before running the
 * pipeline to swap in the feedback loaded from the effective baseline file (the
 * `--baseline` override wins over the configured default), and until then the
 * holder carries no feedback.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
