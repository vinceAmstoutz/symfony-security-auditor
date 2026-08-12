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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * The maintainer-authored false-positive feedback handed to the reviewer:
 * every baselined finding whose entry carries a `reason`. The digest is a
 * stable identity of the whole feedback set, folded into reviewer cache keys
 * so a reason change invalidates verdicts produced under different feedback.
 */
final readonly class ReviewerFeedback
{
    /**
     * @param list<AcceptedFindingFeedback> $entries
     */
    public function __construct(
        public array $entries,
    ) {}

    public static function none(): self
    {
        return new self([]);
    }

    public function isEmpty(): bool
    {
        return [] === $this->entries;
    }

    /**
     * Empty feedback digests to the empty string so cache signatures built
     * without feedback stay byte-identical to those of earlier releases.
     *
     * The digest is order-independent: the entries are sorted before hashing
     * so that re-ordering the same set (e.g. the triage-memory store re-writing
     * its file in a different order between runs) does not spuriously
     * invalidate cached reviewer verdicts.
     *
     * Each entry's `type`/`file`/`title`/`reason` is hashed individually before
     * being joined into that entry's line, and each line is hashed again
     * before joining the whole set — mirroring `ChunkContextKeyDeriver::derive()`
     * at both levels. `file`/`title` are LLM- or file-path-sourced and never
     * NUL-sanitized, so without the field-level hash a NUL byte could shift a
     * value across the `\0` join and make two entries with different
     * `file`/`title` splits produce the exact same line string (e.g.
     * `file="A\0B", title="C"` vs `file="A", title="B\0C"`); the line-level
     * hash alone cannot catch that, since the lines themselves would already
     * be identical.
     */
    public function digest(): string
    {
        if ($this->isEmpty()) {
            return '';
        }

        $lines = array_map(
            static fn (AcceptedFindingFeedback $acceptedFindingFeedback): string => hash('sha256', implode('', [
                hash('sha256', $acceptedFindingFeedback->type),
                hash('sha256', $acceptedFindingFeedback->file),
                hash('sha256', $acceptedFindingFeedback->title),
                hash('sha256', $acceptedFindingFeedback->reason),
            ])),
            $this->entries,
        );
        sort($lines);

        return hash('sha256', implode('', $lines));
    }
}
