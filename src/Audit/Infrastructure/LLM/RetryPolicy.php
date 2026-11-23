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

use Closure;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class RetryPolicy
{
    public const int DEFAULT_MAX_ATTEMPTS = 3;

    public const int DEFAULT_INITIAL_DELAY_MS = 500;

    public const float DEFAULT_BACKOFF_MULTIPLIER = 2.0;

    public const float DEFAULT_JITTER_RATIO = 0.2;

    /**
     * First delay after a 429, long enough for a 60-second rate-limit window
     * to reset.
     */
    public const int DEFAULT_RATE_LIMIT_DELAY_MS = 60_000;

    /**
     * Caps any rate-limit delay, `Retry-After` included, so a provider cannot
     * stall the audit for hours.
     */
    public const int DEFAULT_RATE_LIMIT_MAX_DELAY_MS = 300_000;

    /**
     * Caps a transient-failure delay, which a high `max_attempts` would
     * otherwise grow without bound.
     */
    public const int DEFAULT_MAX_DELAY_MS = 300_000;

    /** @var Closure(): float */
    private Closure $jitterSource;

    /** @param ?Closure(): float $jitterSource returns a float in [0, 1]; defaults to mt_rand()/mt_getrandmax() */
    public function __construct(
        private BackoffSchedule $backoffSchedule = new BackoffSchedule(),
        private RateLimitBackoff $rateLimitBackoff = new RateLimitBackoff(),
        ?Closure $jitterSource = null,
    ) {
        $this->jitterSource = $jitterSource ?? static fn (): float => mt_rand() / mt_getrandmax();
    }

    public function maxAttempts(): int
    {
        return $this->backoffSchedule->maxAttempts;
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function delayMs(int $attempt): int
    {
        if ($attempt < 1) {
            throw InvalidRetryConfigurationException::forNonPositiveAttempt($attempt);
        }

        return (int) round(min($this->computeDelay($this->backoffSchedule->initialDelayMs, $attempt), (float) self::DEFAULT_MAX_DELAY_MS));
    }

    /**
     * Returns the delay before retrying a 429: a positive `$serverHintSeconds`
     * wins, else the rate-limit schedule, jittered upward only so it never
     * undercuts the provider's wait. Clamped to the rate-limit ceiling.
     *
     * @throws InvalidRetryConfigurationException
     */
    public function rateLimitDelayMs(int $attempt, ?int $serverHintSeconds = null): int
    {
        if ($attempt < 1) {
            throw InvalidRetryConfigurationException::forNonPositiveAttempt($attempt);
        }

        if (null !== $serverHintSeconds && $serverHintSeconds > 0) {
            return min($serverHintSeconds * 1_000, $this->rateLimitBackoff->maxDelayMs);
        }

        return (int) round(min($this->computeDelay($this->rateLimitBackoff->initialDelayMs, $attempt, upwardOnlyJitter: true), (float) $this->rateLimitBackoff->maxDelayMs));
    }

    /**
     * Returns rateLimitDelayMs(), or the longer `$suggestedWaitMs`, clamped to
     * the rate-limit ceiling.
     *
     * @throws InvalidRetryConfigurationException
     */
    public function rateLimitDelayAtLeastMs(int $attempt, ?int $serverHintSeconds, int $suggestedWaitMs): int
    {
        return min(max($this->rateLimitDelayMs($attempt, $serverHintSeconds), $suggestedWaitMs), $this->rateLimitBackoff->maxDelayMs);
    }

    /**
     * Returns the unclamped float delay; clamp it before an int cast, which
     * overflows on a large attempt.
     */
    private function computeDelay(int $baseInitialDelayMs, int $attempt, bool $upwardOnlyJitter = false): float
    {
        $baseDelay = $baseInitialDelayMs * ($this->backoffSchedule->backoffMultiplier ** ($attempt - 1));
        $jitterSample = ($this->jitterSource)();
        $jitterFactor = $upwardOnlyJitter
            ? 1.0 + $this->backoffSchedule->jitterRatio * $jitterSample
            : 1.0 + $this->backoffSchedule->jitterRatio * (2.0 * $jitterSample - 1.0);

        return $baseDelay * $jitterFactor;
    }
}
