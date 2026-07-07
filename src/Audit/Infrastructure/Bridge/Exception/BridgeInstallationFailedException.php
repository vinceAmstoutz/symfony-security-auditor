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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception;

use RuntimeException;
use Throwable;

/** @internal not part of the BC promise — see docs/versioning.md */
final class BridgeInstallationFailedException extends RuntimeException
{
    public static function forUnavailableComposer(string $package, Throwable $throwable): self
    {
        return new self(\sprintf('Could not run composer to install the "%s" provider bridge; is composer on the PATH?', $package), previous: $throwable);
    }

    public static function forFailedProcess(string $package, string $errorOutput): self
    {
        return new self(\sprintf('Installing the "%s" provider bridge failed: %s', $package, '' !== $errorOutput ? $errorOutput : 'unknown error'));
    }

    public static function forManifestWriteFailure(string $targetDirectory, Throwable $throwable): self
    {
        return new self(\sprintf('Could not initialize a composer project in "%s": %s', $targetDirectory, $throwable->getMessage()), previous: $throwable);
    }
}
