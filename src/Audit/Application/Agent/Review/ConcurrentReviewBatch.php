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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * The per-finding requests of one concurrency window with their sessions,
 * findings and code contexts, keyed by pending index.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConcurrentReviewBatch
{
    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $requests
     * @param list<int>                                                      $pendingIndexes
     * @param array<int, StructuredReviewCollectionSession>                  $sessions
     * @param list<Vulnerability>                                            $vulnerabilities
     * @param array<int, string>                                             $codeContexts
     */
    public function __construct(
        public array $requests,
        public array $pendingIndexes,
        public array $sessions,
        public array $vulnerabilities,
        public array $codeContexts,
        public bool $bypassCache,
    ) {}

    /**
     * Returns null when the run bypasses the cache.
     */
    public function codeContextForCache(int $index): ?string
    {
        return $this->bypassCache ? null : $this->codeContexts[$index];
    }
}
