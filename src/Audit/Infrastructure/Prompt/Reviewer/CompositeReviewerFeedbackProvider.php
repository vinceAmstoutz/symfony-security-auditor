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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackSnapshotInterface;

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
 * system prompt stable for the whole run.
 *
 * The snapshot is discarded at the start of each run via
 * {@see resetForNewRun()} — called by `RunAuditUseCase::execute()` — so a
 * long-lived process (`mcp:serve`) picks up the entries recorded during the
 * previous run instead of serving the first run's frozen feedback forever.
 *
 * Mutable by design — non-readonly because the snapshot is filled lazily on
 * first read and cleared per run. See .claude/rules/php-classes.md for the
 * opt-out policy.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class CompositeReviewerFeedbackProvider implements ReviewerFeedbackProviderInterface, ReviewerFeedbackSnapshotInterface
{
    private ?ReviewerFeedback $reviewerFeedback = null;

    public function __construct(
        private readonly ReviewerFeedbackProviderInterface $primary,
        private readonly ReviewerFeedbackProviderInterface $secondary,
    ) {}

    #[Override]
    public function feedback(): ReviewerFeedback
    {
        return $this->reviewerFeedback ??= new ReviewerFeedback($this->deduplicated([
            ...$this->primary->feedback()->entries,
            ...$this->secondary->feedback()->entries,
        ]));
    }

    /**
     * Keeps the first entry per finding identity (type+file+title) so a finding
     * present in both the baseline (primary) and triage memory (secondary)
     * occupies a single reviewer-prompt slot instead of two — the baseline
     * reason wins, since primary is spread first.
     *
     * @param list<AcceptedFindingFeedback> $entries
     *
     * @return list<AcceptedFindingFeedback>
     */
    private function deduplicated(array $entries): array
    {
        $unique = [];
        foreach ($entries as $entry) {
            $unique[\sprintf("%s\0%s\0%s", $entry->type, $entry->file, $entry->title)] ??= $entry;
        }

        return array_values($unique);
    }

    #[Override]
    public function resetForNewRun(): void
    {
        $this->reviewerFeedback = null;
    }
}
