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
final class HiddenInputUnavailableException extends RuntimeException
{
    public static function create(Throwable $throwable): self
    {
        return new self('This terminal cannot hide what is typed into it, so no API key was asked for.', previous: $throwable);
    }
}
