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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\Exception;

use InvalidArgumentException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class InvalidRateLimiterConfigurationException extends InvalidArgumentException
{
    public static function forNoEnabledDimension(): self
    {
        return new self('TokenBucketRateLimiter requires at least one rate-limit dimension; wire NullRateLimiter for fully-disabled config.');
    }

    public static function forNegativeEstimatedInputTokens(int $estimatedInputTokens): self
    {
        return new self(\sprintf('estimatedInputTokens must be >= 0, got %d', $estimatedInputTokens));
    }
}
