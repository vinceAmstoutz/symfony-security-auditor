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
use Throwable;

/** @internal not part of the BC promise — see docs/versioning.md */
final class SelfUpdateFailedException extends RuntimeException
{
    public static function forUnresolvableLatestVersion(string $source, ?Throwable $throwable = null): self
    {
        return new self(\sprintf('Could not determine the latest released version from "%s".', $source), previous: $throwable);
    }

    public static function forFailedDownload(string $url, ?Throwable $throwable = null): self
    {
        return new self(\sprintf('Failed to download "%s".', $url), previous: $throwable);
    }

    public static function forUndeterminedBinaryPath(): self
    {
        return new self('Could not determine the path of the running binary to replace; self-update is only supported for the standalone binary.');
    }

    public static function forNonStandaloneRuntime(string $sapi): self
    {
        return new self(\sprintf('self-update is only supported for the standalone binary, but it is running under the "%s" PHP SAPI; reinstall with Composer or the install script instead.', $sapi));
    }

    public static function forChecksumMismatch(string $asset): self
    {
        return new self(\sprintf('Checksum verification failed for "%s"; the download was not trusted and has been discarded.', $asset));
    }

    public static function forUnwritableBinary(string $binaryPath): self
    {
        return new self(\sprintf('The binary at "%s" is not writable; re-run the update with the necessary permissions (e.g. sudo) or reinstall with the install script.', $binaryPath));
    }

    public static function forFailedReplacement(string $binaryPath, Throwable $throwable): self
    {
        return new self(\sprintf('Failed to replace the binary at "%s": %s', $binaryPath, $throwable->getMessage()), previous: $throwable);
    }
}
