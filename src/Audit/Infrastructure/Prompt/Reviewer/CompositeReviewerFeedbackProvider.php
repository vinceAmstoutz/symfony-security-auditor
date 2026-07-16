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
 * Merges feedback from two sources — the baseline-backed
 * {@see ReviewerFeedbackHolder} and, when `audit.triage_memory` is enabled,
 * the reviewer's own cross-run rejections — into the single feedback set the
 * reviewer prompt and cache key see.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CompositeReviewerFeedbackProvider implements ReviewerFeedbackProviderInterface
{
    public function __construct(
        private ReviewerFeedbackProviderInterface $primary,
        private ReviewerFeedbackProviderInterface $secondary,
    ) {}

    #[Override]
    public function feedback(): ReviewerFeedback
    {
        return new ReviewerFeedback([
            ...$this->primary->feedback()->entries,
            ...$this->secondary->feedback()->entries,
        ]);
    }
}
