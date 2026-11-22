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

use DateTimeImmutable;

/**
 * Throttles the calls between `LLMClientInterface` and the provider, so the
 * audit stays inside the provider quota.
 */
interface RateLimiterInterface
{
    /**
     * Blocks until a request of `$estimatedInputTokens` input tokens fits
     * inside the rate-limit window.
     */
    public function acquire(int $estimatedInputTokens): void;

    /**
     * Replaces the estimate with a successful call's actual token usage.
     */
    public function record(int $inputTokens, int $outputTokens): void;

    /**
     * Holds every later `acquire()` until `$until`, such as a server-issued
     * `Retry-After`.
     */
    public function pauseUntil(DateTimeImmutable $until): void;
}
