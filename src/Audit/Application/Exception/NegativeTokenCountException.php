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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception;

use InvalidArgumentException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class NegativeTokenCountException extends InvalidArgumentException
{
    public static function forInputTokens(int $inputTokens): self
    {
        return new self(\sprintf('Input tokens must be >= 0, got %d', $inputTokens));
    }

    public static function forOutputTokens(int $outputTokens): self
    {
        return new self(\sprintf('Output tokens must be >= 0, got %d', $outputTokens));
    }

    public static function forCacheReadTokens(int $cacheReadTokens): self
    {
        return new self(\sprintf('Cache read tokens must be >= 0, got %d', $cacheReadTokens));
    }

    public static function forCacheCreationTokens(int $cacheCreationTokens): self
    {
        return new self(\sprintf('Cache creation tokens must be >= 0, got %d', $cacheCreationTokens));
    }
}
