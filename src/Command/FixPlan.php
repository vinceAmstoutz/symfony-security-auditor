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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/**
 * The outcome of every suggested fix of a report, and the content each file
 * the fixes that apply change ends up with, keyed by its absolute path.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FixPlan
{
    /**
     * @param list<FixOutcome>      $outcomes
     * @param array<string, string> $contents
     */
    public function __construct(
        public array $outcomes,
        public array $contents,
    ) {}

    public function appliedCount(): int
    {
        return \count(array_filter($this->outcomes, static fn (FixOutcome $fixOutcome): bool => $fixOutcome->applies()));
    }
}
