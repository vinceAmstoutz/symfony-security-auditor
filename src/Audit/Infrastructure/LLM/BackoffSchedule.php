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
 * The standard exponential-backoff schedule for transient-failure retries.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BackoffSchedule
{
    public function __construct(
        public int $maxAttempts = RetryPolicy::DEFAULT_MAX_ATTEMPTS,
        public int $initialDelayMs = RetryPolicy::DEFAULT_INITIAL_DELAY_MS,
        public float $backoffMultiplier = RetryPolicy::DEFAULT_BACKOFF_MULTIPLIER,
        public float $jitterRatio = RetryPolicy::DEFAULT_JITTER_RATIO,
    ) {
        if ($maxAttempts < 1) {
            throw InvalidRetryConfigurationException::forNonPositiveMaxAttempts($maxAttempts);
        }

        if ($initialDelayMs < 0) {
            throw InvalidRetryConfigurationException::forNegativeInitialDelay($initialDelayMs);
        }

        if ($backoffMultiplier < 1.0) {
            throw InvalidRetryConfigurationException::forLowBackoffMultiplier($backoffMultiplier);
        }

        if ($jitterRatio < 0.0 || $jitterRatio > 1.0) {
            throw InvalidRetryConfigurationException::forOutOfRangeJitterRatio($jitterRatio);
        }
    }
}
