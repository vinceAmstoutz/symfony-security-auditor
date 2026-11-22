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
 * Findings split against the verdict cache: the hits keyed by original index
 * and the misses with their indexes.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CachePartition
{
    /**
     * @param array<string, string>     $codeContexts
     * @param array<int, Vulnerability> $reviewed
     * @param list<int>                 $missIndexes
     * @param list<Vulnerability>       $misses
     */
    public function __construct(
        public array $codeContexts,
        public array $reviewed,
        public array $missIndexes,
        public array $misses,
    ) {}
}
