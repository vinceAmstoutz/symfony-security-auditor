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
use Symfony\Component\Filesystem\Exception\IOException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class StandaloneConfigWriteException extends RuntimeException
{
    public static function fromIOException(string $configFile, IOException $ioException): self
    {
        return new self(\sprintf('Failed to write configuration to "%s": %s', $configFile, $ioException->getMessage()), previous: $ioException);
    }
}
