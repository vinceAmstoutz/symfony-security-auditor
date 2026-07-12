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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;

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
    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function __construct(
        public ?int $requestsPerMinute,
        public ?int $inputTokensPerMinute,
        public ?int $outputTokensPerMinute,
    ) {
        if (null !== $requestsPerMinute && $requestsPerMinute < 1) {
            throw InvalidRateLimitConfigurationException::forNonPositiveRequestsPerMinute($requestsPerMinute);
        }

        if (null !== $inputTokensPerMinute && $inputTokensPerMinute < 1) {
            throw InvalidRateLimitConfigurationException::forNonPositiveInputTokensPerMinute($inputTokensPerMinute);
        }

        if (null !== $outputTokensPerMinute && $outputTokensPerMinute < 1) {
            throw InvalidRateLimitConfigurationException::forNonPositiveOutputTokensPerMinute($outputTokensPerMinute);
        }
    }

    public function isEnabled(): bool
    {
        return null !== $this->requestsPerMinute
            || null !== $this->inputTokensPerMinute
            || null !== $this->outputTokensPerMinute;
    }
}
