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
     */
    public function digest(): string
    {
        if ($this->isEmpty()) {
            return '';
        }

        $lines = array_map(
            static fn (AcceptedFindingFeedback $acceptedFindingFeedback): string => \sprintf(
                "%s\0%s\0%s\0%s",
                $acceptedFindingFeedback->type,
                $acceptedFindingFeedback->file,
                $acceptedFindingFeedback->title,
                $acceptedFindingFeedback->reason,
            ),
            $this->entries,
        );

        return hash('sha256', implode("\n", $lines));
    }
}
