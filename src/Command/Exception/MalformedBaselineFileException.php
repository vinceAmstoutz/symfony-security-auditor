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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Exception;

use RuntimeException;
use Throwable;

/** @internal not part of the BC promise — see docs/versioning.md */
final class MalformedBaselineFileException extends RuntimeException
{
    public static function notAJsonArrayOfStrings(string $path): self
    {
        return new self(\sprintf('Baseline file "%s" must contain a JSON array of fingerprint strings.', $path));
    }

    public static function fromJsonException(string $path, Throwable $throwable): self
    {
        return new self(\sprintf('Baseline file "%s" is not valid JSON: %s', $path, $throwable->getMessage()), previous: $throwable);
    }

    public static function fromIOException(string $path, Throwable $throwable): self
    {
        return new self(\sprintf('Baseline file "%s" could not be read or written: %s', $path, $throwable->getMessage()), previous: $throwable);
    }
}
