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
final class UnreadableCredentialFileException extends RuntimeException
{
    public static function forPath(string $path): self
    {
        return new self(\sprintf('The credential file "%s", referenced by your config, could not be read.', $path));
    }

    public static function forBlankFile(string $path): self
    {
        return new self(\sprintf('The credential file "%s", referenced by your config, is empty.', $path));
    }
}
