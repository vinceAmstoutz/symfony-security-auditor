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

final class InvalidAuditCostException extends InvalidArgumentException
{
    public static function forNegativeInputTokens(int $inputTokens): self
    {
        return new self(\sprintf('inputTokens must be >= 0, got %d', $inputTokens));
    }

    public static function forNegativeOutputTokens(int $outputTokens): self
    {
        return new self(\sprintf('outputTokens must be >= 0, got %d', $outputTokens));
    }

    public static function forNegativeCost(float $estimatedCostUsd): self
    {
        return new self(\sprintf('estimatedCostUsd must be >= 0.0, got %f', $estimatedCostUsd));
    }
}
