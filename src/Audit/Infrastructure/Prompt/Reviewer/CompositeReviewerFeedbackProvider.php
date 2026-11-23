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
 * Merges the primary feedback (the baseline) with the secondary one (triage
 * memory) and freezes the result on first read, so the reviewer prompt and
 * cache key stay stable for the whole run while triage memory grows.
 * {@see resetForNewRun()} discards the snapshot.
 *
 * Not readonly: holds the snapshot of one run (stateful collaborator, see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
     * Keeps the first entry of each type, file and title, the primary one when
     * both have it. Each field is hashed on its own, so a separator in `file`
     * or `title` cannot merge two findings.
     *
     * @param list<AcceptedFindingFeedback> $entries
     *
     * @return list<AcceptedFindingFeedback>
     */
    private function deduplicated(array $entries): array
    {
        $unique = [];
        foreach ($entries as $entry) {
            $key = hash('sha256', implode('', [
                hash('sha256', $entry->type),
                hash('sha256', $entry->file),
                hash('sha256', $entry->title),
            ]));
            $unique[$key] ??= $entry;
        }

        return array_values($unique);
    }

    #[Override]
    public function resetForNewRun(): void
    {
        $this->reviewerFeedback = null;
    }
}
