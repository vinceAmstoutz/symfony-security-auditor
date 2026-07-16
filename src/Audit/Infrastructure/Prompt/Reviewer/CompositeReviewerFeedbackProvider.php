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
 * reviewer prompt and cache key see, snapshotting it once per run.
 *
 * The merged set is memoized on first read. The triage-memory secondary is
 * written to mid-run — every reviewer rejection appends an entry — so reading
 * it live would shift the reviewer cache-key digest between findings within a
 * single run, making every verdict after the first miss its own freshly-written
 * cache entry. Freezing the set on first read keeps the digest and the reviewer
 * system prompt stable for the whole run; the next run picks up the entries
 * recorded during this one.
 *
 * Mutable by design — non-readonly because the snapshot is filled lazily on
 * first read. See .claude/rules/php-classes.md for the opt-out policy.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class CompositeReviewerFeedbackProvider implements ReviewerFeedbackProviderInterface
{
    private ?ReviewerFeedback $reviewerFeedback = null;

    public function __construct(
        private readonly ReviewerFeedbackProviderInterface $primary,
        private readonly ReviewerFeedbackProviderInterface $secondary,
    ) {}

    #[Override]
    public function feedback(): ReviewerFeedback
    {
        return $this->reviewerFeedback ??= new ReviewerFeedback([
            ...$this->primary->feedback()->entries,
            ...$this->secondary->feedback()->entries,
        ]);
    }
}
