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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception;

use RuntimeException;
use Throwable;

final class AdvisorySourceUnavailableException extends RuntimeException
{
    public static function forFailedProcess(string $projectPath, string $reason, ?Throwable $throwable = null): self
    {
        return new self(
            \sprintf('Composer audit failed for project "%s": %s', $projectPath, $reason),
            previous: $throwable,
        );
    }

    public static function forBinaryNotFound(?Throwable $throwable = null): self
    {
        return new self(
            'composer binary not found on PATH; cannot run advisory audit',
            previous: $throwable,
        );
    }
}
