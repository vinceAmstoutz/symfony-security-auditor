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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnsupportedSelfUpdatePlatformException extends RuntimeException
{
    public static function forPlatform(string $osFamily, string $machine): self
    {
        return new self(\sprintf('Self-update does not support the "%s" / "%s" platform; download the binary for your platform from the releases page instead.', $osFamily, $machine));
    }
}
