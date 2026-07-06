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

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class RetryPolicy
{
    public const int DEFAULT_MAX_ATTEMPTS = 3;

    public const int DEFAULT_INITIAL_DELAY_MS = 500;

    public const float DEFAULT_BACKOFF_MULTIPLIER = 2.0;

    public const float DEFAULT_JITTER_RATIO = 0.2;

    /**
     * Initial delay used when retrying after a rate-limit (429) response.
     * Anthropic's rate-limit windows reset within 60 seconds, so this default
     * ensures the first retry does not fire until the window has elapsed.
     */
    public const int DEFAULT_RATE_LIMIT_DELAY_MS = 60_000;

    /**
     * Upper bound applied to any rate-limit delay — exponential backoff or
     * server-provided `Retry-After` — so a misbehaving provider cannot wedge
     * the audit for hours.
     */
    public const int DEFAULT_RATE_LIMIT_MAX_DELAY_MS = 300_000;

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

        return $this->computeDelay($this->backoffSchedule->initialDelayMs, $attempt);
    }

    /**
     * Returns the delay before retrying a rate-limited (429) request.
     *
     * When `$serverHintSeconds` is a positive integer (typically parsed from a
     * `Retry-After` response header via `RetryAfterHeaderParser`), the hint
     * wins over the local exponential schedule. Otherwise the delay is
     * `rateLimitInitialDelayMs` grown by `backoffMultiplier ** (attempt − 1)`
     * with the same jitter as `delayMs()`. The result is always clamped to
     * `rateLimitMaxDelayMs` so a hostile provider cannot push the wait past
     * a sane ceiling.
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

        return min($this->computeDelay($this->rateLimitBackoff->initialDelayMs, $attempt, upwardOnlyJitter: true), $this->rateLimitBackoff->maxDelayMs);
    }

    private function computeDelay(int $baseInitialDelayMs, int $attempt, bool $upwardOnlyJitter = false): int
    {
        $baseDelay = $baseInitialDelayMs * ($this->backoffSchedule->backoffMultiplier ** ($attempt - 1));
        $jitterSample = ($this->jitterSource)();
        $jitterFactor = $upwardOnlyJitter
            ? 1.0 + $this->backoffSchedule->jitterRatio * $jitterSample
            : 1.0 + $this->backoffSchedule->jitterRatio * (2.0 * $jitterSample - 1.0);

        return (int) round($baseDelay * $jitterFactor);
    }
}
