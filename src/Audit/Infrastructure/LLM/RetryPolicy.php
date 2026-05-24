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
use InvalidArgumentException;

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

    /** @var Closure(): float */
    private Closure $jitterSource;

    /** @param ?Closure(): float $jitterSource returns a float in [0, 1]; defaults to mt_rand()/mt_getrandmax() */
    public function __construct(
        private int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS,
        private int $initialDelayMs = self::DEFAULT_INITIAL_DELAY_MS,
        private float $backoffMultiplier = self::DEFAULT_BACKOFF_MULTIPLIER,
        private float $jitterRatio = self::DEFAULT_JITTER_RATIO,
        private int $rateLimitInitialDelayMs = self::DEFAULT_RATE_LIMIT_DELAY_MS,
        ?Closure $jitterSource = null,
    ) {
        if ($maxAttempts < 1) {
            throw new InvalidArgumentException(\sprintf('maxAttempts must be >= 1, got %d', $maxAttempts));
        }

        if ($initialDelayMs < 0) {
            throw new InvalidArgumentException(\sprintf('initialDelayMs must be >= 0, got %d', $initialDelayMs));
        }

        if ($backoffMultiplier < 1.0) {
            throw new InvalidArgumentException(\sprintf('backoffMultiplier must be >= 1.0, got %f', $backoffMultiplier));
        }

        if ($jitterRatio < 0.0 || $jitterRatio > 1.0) {
            throw new InvalidArgumentException(\sprintf('jitterRatio must be in [0.0, 1.0], got %f', $jitterRatio));
        }

        if ($rateLimitInitialDelayMs < 0) {
            throw new InvalidArgumentException(\sprintf('rateLimitInitialDelayMs must be >= 0, got %d', $rateLimitInitialDelayMs));
        }

        $this->jitterSource = $jitterSource ?? static fn (): float => mt_rand() / mt_getrandmax();
    }

    public function maxAttempts(): int
    {
        return $this->maxAttempts;
    }

    public function delayMs(int $attempt): int
    {
        if ($attempt < 1) {
            throw new InvalidArgumentException(\sprintf('attempt must be >= 1, got %d', $attempt));
        }

        return $this->computeDelay($this->initialDelayMs, $attempt);
    }

    /**
     * Returns the delay before retrying a rate-limited (429) request.
     * Uses `rateLimitInitialDelayMs` as the base, applying the same
     * backoff multiplier and jitter as `delayMs()`.
     */
    public function rateLimitDelayMs(int $attempt): int
    {
        if ($attempt < 1) {
            throw new InvalidArgumentException(\sprintf('attempt must be >= 1, got %d', $attempt));
        }

        return $this->computeDelay($this->rateLimitInitialDelayMs, $attempt);
    }

    private function computeDelay(int $baseInitialDelayMs, int $attempt): int
    {
        $baseDelay = $baseInitialDelayMs * ($this->backoffMultiplier ** ($attempt - 1));
        $jitterFactor = 1.0 + $this->jitterRatio * (2.0 * ($this->jitterSource)() - 1.0);

        return (int) round($baseDelay * $jitterFactor);
    }
}
