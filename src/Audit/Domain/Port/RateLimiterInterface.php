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
 * Pre-call throttle around the LLM seam.
 *
 * Implementations sit between `LLMClientInterface` and the provider HTTP call.
 * `acquire()` blocks until the next request fits inside the configured window
 * so the audit never punches through the provider quota; `record()` lets the
 * limiter reconcile its estimate with the post-call actuals; `pauseUntil()`
 * lets the LLM client propagate a server-issued `Retry-After` into the bucket
 * so subsequent in-flight chunks honor the same freeze without each having
 * to discover it independently.
 */
interface RateLimiterInterface
{
    /**
     * Block (sleep) until a request of `$estimatedInputTokens` input tokens
     * fits inside the rate-limit window. May return immediately when the
     * bucket has capacity or when limiting is disabled.
     */
    public function acquire(int $estimatedInputTokens): void;

    /**
     * Reconcile the limiter's estimate with the response's actual token usage.
     * Called after a successful LLM call so subsequent `acquire()` decisions
     * are based on real consumption rather than the pre-call estimate.
     */
    public function record(int $inputTokens, int $outputTokens): void;

    /**
     * Freeze all subsequent `acquire()` calls until `$until`. Used to honor
     * a server-issued `Retry-After` so concurrent or follow-up calls do not
     * pile on while the provider window is closed.
     */
    public function pauseUntil(DateTimeImmutable $until): void;
}
