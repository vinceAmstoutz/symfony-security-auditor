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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;

/**
 * The retry/throttle stack: retry policy + transient-failure classification,
 * Retry-After parsing, the sleeper, and the shared rate limiter.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformResilienceConfig
{
    public function __construct(
        public RetryPolicy $retryPolicy = new RetryPolicy(),
        public TransientFailureClassifier $transientFailureClassifier = new TransientFailureClassifier(),
        public RetryAfterHeaderParser $retryAfterHeaderParser = new RetryAfterHeaderParser(),
        public SleeperInterface $sleeper = new UsleepSleeper(),
        public RateLimiterInterface $rateLimiter = new NullRateLimiter(),
    ) {}
}
