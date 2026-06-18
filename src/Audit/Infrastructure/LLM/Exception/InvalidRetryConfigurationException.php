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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception;

use InvalidArgumentException;

final class InvalidRetryConfigurationException extends InvalidArgumentException
{
    public static function forNonPositiveMaxAttempts(int $maxAttempts): self
    {
        return new self(\sprintf('maxAttempts must be >= 1, got %d', $maxAttempts));
    }

    public static function forNegativeInitialDelay(int $initialDelayMs): self
    {
        return new self(\sprintf('initialDelayMs must be >= 0, got %d', $initialDelayMs));
    }

    public static function forLowBackoffMultiplier(float $backoffMultiplier): self
    {
        return new self(\sprintf('backoffMultiplier must be >= 1.0, got %f', $backoffMultiplier));
    }

    public static function forOutOfRangeJitterRatio(float $jitterRatio): self
    {
        return new self(\sprintf('jitterRatio must be in [0.0, 1.0], got %f', $jitterRatio));
    }

    public static function forNegativeRateLimitInitialDelay(int $rateLimitInitialDelayMs): self
    {
        return new self(\sprintf('rateLimitInitialDelayMs must be >= 0, got %d', $rateLimitInitialDelayMs));
    }

    public static function forNegativeRateLimitMaxDelay(int $rateLimitMaxDelayMs): self
    {
        return new self(\sprintf('rateLimitMaxDelayMs must be >= 0, got %d', $rateLimitMaxDelayMs));
    }
}
