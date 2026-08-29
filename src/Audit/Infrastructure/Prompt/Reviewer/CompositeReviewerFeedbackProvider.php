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
 * Merges the baseline-backed {@see ReviewerFeedbackHolder} and, when
 * `audit.triage_memory` is on, the reviewer's own cross-run rejections into the
 * single feedback set the reviewer prompt and cache key see.
 *
 * The set is frozen on first read because triage memory is appended mid-run:
 * reading it live would shift the reviewer cache-key digest between findings, so
 * every verdict after the first would miss its own entry.
 * {@see resetForNewRun()} discards the snapshot per run, so a long-lived
 * `mcp:serve` process does not serve the first run's feedback forever.
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
     * `file`/`title` are LLM- or path-sourced and never NUL-sanitized, so each
     * field is hashed individually before joining the key — mirroring
     * `ChunkContextKeyDeriver::derive()` — so a NUL cannot shift a value across
     * the boundary and collide two findings onto one dedup key.
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
