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

/**
 * A finding awaiting its verdict, with its position in the caller's list and
 * the code context to cache the verdict under, null when the cache is
 * bypassed.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PendingReview
{
    public function __construct(
        public int $index,
        public Vulnerability $vulnerability,
        public ?string $cacheContext,
    ) {}
}
