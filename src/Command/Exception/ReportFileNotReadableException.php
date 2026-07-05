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

/** @internal not part of the BC promise — see docs/versioning.md */
final class ReportFileNotReadableException extends RuntimeException
{
    public static function forPath(string $path): self
    {
        return new self(\sprintf('Report file "%s" does not exist or is not readable.', $path));
    }
}
