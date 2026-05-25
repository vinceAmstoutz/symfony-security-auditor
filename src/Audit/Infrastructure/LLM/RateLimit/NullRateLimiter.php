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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit;

use DateTimeImmutable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;

/**
 * No-op rate limiter wired when none of the `audit.rate_limit.*` dimensions
 * are configured. Preserves the pre-existing reactive-retry-only behavior.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NullRateLimiter implements RateLimiterInterface
{
    public function acquire(int $estimatedInputTokens): void
    {
        // No throttle configured — let the call through immediately.
    }

    public function record(int $inputTokens, int $outputTokens): void
    {
        // Nothing to reconcile when no bucket exists.
    }

    public function pauseUntil(DateTimeImmutable $until): void
    {
        // No bucket to freeze.
    }
}
