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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class AmbiguousPlatformException extends RuntimeException
{
    public static function create(): self
    {
        return new self('Several platforms are configured but none is selected. Set the top-level "provider:" key to the one to use.');
    }
}
