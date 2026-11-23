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
 * The `audit.rate_limit.*` configuration. A null dimension is not limited;
 * with all three null, no rate limiter runs.
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
