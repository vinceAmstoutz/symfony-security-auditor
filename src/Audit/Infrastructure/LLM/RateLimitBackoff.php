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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;

/**
 * The 429 rate-limit retry schedule: first-retry delay and a hard ceiling.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RateLimitBackoff
{
    public function __construct(
        public int $initialDelayMs = RetryPolicy::DEFAULT_RATE_LIMIT_DELAY_MS,
        public int $maxDelayMs = RetryPolicy::DEFAULT_RATE_LIMIT_MAX_DELAY_MS,
    ) {
        if ($initialDelayMs < 0) {
            throw InvalidRetryConfigurationException::forNegativeRateLimitInitialDelay($initialDelayMs);
        }

        if ($maxDelayMs < 0) {
            throw InvalidRetryConfigurationException::forNegativeRateLimitMaxDelay($maxDelayMs);
        }
    }
}
