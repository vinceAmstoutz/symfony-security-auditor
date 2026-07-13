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
 * The outcome of planning a baseline merge: the existing entries to keep
 * (raw payloads preserved), the report findings not yet covered by any
 * entry, and how many stale entries a prune dropped.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BaselineMergePlan
{
    /**
     * @param list<BaselineEntry> $keptEntries
     * @param list<DiffFinding>   $newFindings
     */
    public function __construct(
        public array $keptEntries,
        public array $newFindings,
        public int $prunedCount,
    ) {}
}
