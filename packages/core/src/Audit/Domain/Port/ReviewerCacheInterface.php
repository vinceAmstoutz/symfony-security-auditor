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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Per-finding reviewer-verdict cache, keyed by the finding's stable content
 * (everything the reviewer sees except the non-deterministic `id`) plus the
 * reviewed file's code context, so a repeated audit of unchanged code reuses the
 * prior verdict instead of paying for another reviewer call.
 *
 * Stored payloads are the raw review dicts the reviewer produces, ready to be
 * re-applied. The agent tolerates partial payloads, so implementations need not
 * validate beyond JSON parsing.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ReviewerCacheInterface
{
    /**
     * @return array<string, mixed>|null the raw review dict, or null on miss
     */
    public function get(Vulnerability $vulnerability, string $codeContext): ?array;

    /**
     * @param array<string, mixed> $review
     */
    public function store(Vulnerability $vulnerability, string $codeContext, array $review): void;
}
