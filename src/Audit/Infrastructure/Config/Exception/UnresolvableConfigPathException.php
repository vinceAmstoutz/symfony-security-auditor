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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnresolvableConfigPathException extends RuntimeException
{
    public static function missingHome(): self
    {
        return new self('Cannot resolve the user configuration directory: neither the relevant XDG base-directory variable nor $HOME is set.');
    }
}
