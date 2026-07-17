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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;

/**
 * Persists a rejected finding's reviewer explanation to triage memory in one
 * step, so every review path — single, structured, concurrent, and batched —
 * records the same cross-run feedback instead of only some of them.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RejectionTriageRecorder
{
    /**
     * @param array<string, mixed>|list<array<string, mixed>> $review
     */
    public static function record(
        VerdictApplier $verdictApplier,
        TriageMemoryRecorderInterface $triageMemoryRecorder,
        Vulnerability $vulnerability,
        array $review,
    ): void {
        if ($vulnerability->isReviewerValidated()) {
            return;
        }

        $reviewerNotes = $verdictApplier->normalize($review)['reviewer_notes'] ?? null;
        if (!\is_string($reviewerNotes) || '' === trim($reviewerNotes)) {
            return;
        }

        $triageMemoryRecorder->record($vulnerability->type()->value, $vulnerability->filePath(), $vulnerability->title(), $vulnerability->lineStart(), $reviewerNotes);
    }
}
