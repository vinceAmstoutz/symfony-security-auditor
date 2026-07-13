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
 * Mutable delegate that wires the ReviewerFeedbackProviderInterface seam
 * between DI container construction time and command invocation time.
 *
 * The reviewer prompt builder and the reviewer cache receive this holder as
 * the ReviewerFeedbackProviderInterface implementation. AuditCommand calls
 * set() before running the pipeline to swap in the feedback loaded from the
 * effective baseline file (the `--baseline` CLI override wins over the
 * configured default). Prior to that call the holder carries no feedback.
 *
 * Mutable by design — non-readonly because the feedback is set after
 * construction. See .claude/rules/php-classes.md for the opt-out policy.
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
