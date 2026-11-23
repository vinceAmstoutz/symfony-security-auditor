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
 * The maintainer's false-positive feedback handed to the reviewer: every
 * baselined finding whose entry carries a `reason`. Its digest is part of the
 * reviewer cache keys, so a changed reason invalidates cached verdicts.
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
     * Empty for empty feedback, which leaves cache keys built without feedback
     * unchanged. Independent of the entries' order. Hashes each field, then
     * each entry, before joining, so a NUL byte shifted across a field boundary
     * (`file="A\0B", title="C"` against `file="A", title="B\0C"`) cannot
     * collide.
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
