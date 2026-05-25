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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

use InvalidArgumentException;

/**
 * Typed shape of the `audit.rate_limit.*` configuration tree.
 *
 * Each dimension is independently nullable so an opt-in is partial by default:
 * configure only the dimensions your provider actually enforces. When every
 * dimension is null the bundle wires `NullRateLimiter` and behavior matches
 * the pre-existing retry-only path.
 */
final readonly class RateLimitConfiguration
{
    public function __construct(
        public ?int $requestsPerMinute,
        public ?int $inputTokensPerMinute,
        public ?int $outputTokensPerMinute,
    ) {
        if (null !== $requestsPerMinute && $requestsPerMinute < 1) {
            throw new InvalidArgumentException(\sprintf('requestsPerMinute must be >= 1 or null, got %d', $requestsPerMinute));
        }

        if (null !== $inputTokensPerMinute && $inputTokensPerMinute < 1) {
            throw new InvalidArgumentException(\sprintf('inputTokensPerMinute must be >= 1 or null, got %d', $inputTokensPerMinute));
        }

        if (null !== $outputTokensPerMinute && $outputTokensPerMinute < 1) {
            throw new InvalidArgumentException(\sprintf('outputTokensPerMinute must be >= 1 or null, got %d', $outputTokensPerMinute));
        }
    }

    public function isEnabled(): bool
    {
        return null !== $this->requestsPerMinute
            || null !== $this->inputTokensPerMinute
            || null !== $this->outputTokensPerMinute;
    }
}
