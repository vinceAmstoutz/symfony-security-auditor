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

/**
 * Pure-math exponential-backoff policy with configurable jitter.
 *
 * `delayMs($attempt)` is deterministic given a fixed jitter source: the base
 * delay grows as `initialDelayMs * backoffMultiplier ^ (attempt - 1)`, then a
 * jitter factor in `[1 - jitterRatio, 1 + jitterRatio]` scales the result.
 *
 * Inject `$jitterSource` in tests for reproducible delays.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RetryPolicy
{
    public const int DEFAULT_MAX_ATTEMPTS = 3;

    public const int DEFAULT_INITIAL_DELAY_MS = 500;

    public const float DEFAULT_BACKOFF_MULTIPLIER = 2.0;

    public const float DEFAULT_JITTER_RATIO = 0.2;

    /** @var Closure(): float */
    private Closure $jitterSource;

    /**
     * @param ?Closure(): float $jitterSource returns a float in [0, 1]; defaults to mt_rand()/mt_getrandmax()
     */
    public function __construct(
        private int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS,
        private int $initialDelayMs = self::DEFAULT_INITIAL_DELAY_MS,
        private float $backoffMultiplier = self::DEFAULT_BACKOFF_MULTIPLIER,
        private float $jitterRatio = self::DEFAULT_JITTER_RATIO,
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

        $this->jitterSource = $jitterSource ?? static fn (): float => mt_rand() / mt_getrandmax();
    }

    public function maxAttempts(): int
    {
        return $this->maxAttempts;
    }

    /**
     * Returns the delay before retry attempt `$attempt`. Attempt 1 is the first retry
     * (after the initial call failed); subsequent attempts grow geometrically.
     */
    public function delayMs(int $attempt): int
    {
        if ($attempt < 1) {
            throw new InvalidArgumentException(\sprintf('attempt must be >= 1, got %d', $attempt));
        }

        $baseDelay = $this->initialDelayMs * ($this->backoffMultiplier ** ($attempt - 1));
        $jitterFactor = 1.0 + $this->jitterRatio * (2.0 * ($this->jitterSource)() - 1.0);

        return (int) max(0, round($baseDelay * $jitterFactor));
    }
}
