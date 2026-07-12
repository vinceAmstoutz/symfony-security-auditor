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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

use InvalidArgumentException;

final class InvalidRateLimitConfigurationException extends InvalidArgumentException
{
    public static function forNonPositiveRequestsPerMinute(int $requestsPerMinute): self
    {
        return new self(\sprintf('requestsPerMinute must be >= 1 or null, got %d', $requestsPerMinute));
    }

    public static function forNonPositiveInputTokensPerMinute(int $inputTokensPerMinute): self
    {
        return new self(\sprintf('inputTokensPerMinute must be >= 1 or null, got %d', $inputTokensPerMinute));
    }

    public static function forNonPositiveOutputTokensPerMinute(int $outputTokensPerMinute): self
    {
        return new self(\sprintf('outputTokensPerMinute must be >= 1 or null, got %d', $outputTokensPerMinute));
    }
}
