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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Per-finding reviewer-verdict cache. The key is derived from the finding's
 * stable content (everything the reviewer sees except the non-deterministic
 * `id`) plus the reviewed file's code context, so a repeated audit of unchanged
 * code reuses the prior verdict instead of paying for another reviewer LLM
 * call. A cache hit short-circuits the call entirely.
 *
 * Stored payloads are the raw review dicts the reviewer produces (`accepted`,
 * `adjusted_severity`, `corrected_type`, …), ready to be re-applied. The agent
 * tolerates partial payloads, so implementations need not validate beyond JSON
 * parsing.
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
