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

final class InvalidTokenUsageException extends InvalidArgumentException
{
    public static function forNegativeInputTokens(int $inputTokens): self
    {
        return new self(\sprintf('Input tokens must be >= 0, got %d', $inputTokens));
    }

    public static function forNegativeOutputTokens(int $outputTokens): self
    {
        return new self(\sprintf('Output tokens must be >= 0, got %d', $outputTokens));
    }

    public static function forNegativeCacheReadTokens(int $cacheReadTokens): self
    {
        return new self(\sprintf('Cache read tokens must be >= 0, got %d', $cacheReadTokens));
    }

    public static function forNegativeCacheCreationTokens(int $cacheCreationTokens): self
    {
        return new self(\sprintf('Cache creation tokens must be >= 0, got %d', $cacheCreationTokens));
    }
}
