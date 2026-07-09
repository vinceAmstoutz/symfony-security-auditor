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
use Symfony\Component\Filesystem\Exception\IOException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class ReportWriteFailedException extends RuntimeException
{
    public static function fromIOException(string $path, IOException $ioException): self
    {
        return new self(\sprintf('Failed to write report to "%s": %s', $path, $ioException->getMessage()), previous: $ioException);
    }
}
