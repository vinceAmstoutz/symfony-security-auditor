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
 * Immutable input snapshot of one concurrency window: the per-finding requests
 * and the parallel collections (collection sessions, vulnerabilities,
 * contexts) keyed so each pending index resolves to its finding.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
    ) {}
}
