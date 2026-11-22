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
 * Per-finding cache of reviewer verdicts, keyed by everything the reviewer
 * sees of the finding but its `id`, plus the code context. A hit skips the LLM
 * call.
 *
 * Payloads are the raw review dicts (`accepted`, `adjusted_severity`,
 * `corrected_type`, …). The agent tolerates partial payloads, so an
 * implementation validates nothing beyond JSON.
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
