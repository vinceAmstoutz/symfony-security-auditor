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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception;

use InvalidArgumentException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class SecretScrubberConfigurationException extends InvalidArgumentException
{
    public static function forInvalidPattern(string $pattern, string $error): self
    {
        return new self(\sprintf('Invalid secret-scrubbing pattern %s: %s', $pattern, $error));
    }
}
