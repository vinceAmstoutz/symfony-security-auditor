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
final class UnknownPlatformProviderException extends RuntimeException
{
    public static function forProvider(string $provider): self
    {
        return new self(\sprintf('The selected provider "%s" is not present in the "platform:" block of your config.', $provider));
    }
}
