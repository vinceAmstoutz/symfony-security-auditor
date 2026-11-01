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
        return new self(\sprintf('Could not run composer to install the "%s" provider bridge.', $package), previous: $throwable);
    }

    public static function forUnlocatableBinary(Throwable $throwable): self
    {
        return new self(\sprintf('Could not start this binary to install the provider bridge: %s', $throwable->getMessage()), previous: $throwable);
    }

    public static function forUnbundledComposerPhar(string $version, string $bundledPhar): self
    {
        return new self(\sprintf('This build bundles no composer.phar %s to install the provider bridge with: "%s" does not exist.', $version, $bundledPhar));
    }

    public static function forUncopyableComposerPhar(string $version, string $directory, Throwable $throwable): self
    {
        return new self(\sprintf('Could not copy composer.phar %s to "%s": %s', $version, $directory, $throwable->getMessage()), previous: $throwable);
    }

    public static function forTamperedComposerPhar(string $version): self
    {
        return new self(\sprintf('The composer.phar %s this binary bundles does not match its pinned SHA-256 checksum; it was discarded. Reinstall the binary.', $version));
    }

    public static function forFailedProcess(string $package, string $errorOutput): self
    {
        return new self(\sprintf('Installing the "%s" provider bridge failed: %s', $package, '' !== $errorOutput ? $errorOutput : 'unknown error'));
    }

    public static function forUnreadableManifest(string $manifest, Throwable $throwable): self
    {
        return new self(\sprintf('Could not read the composer manifest "%s" of the bridge directory: %s Fix or delete it, then run init again.', $manifest, $throwable->getMessage()), previous: $throwable);
    }

    public static function forManifestWriteFailure(string $targetDirectory, Throwable $throwable): self
    {
        return new self(\sprintf('Could not initialize a composer project in "%s": %s', $targetDirectory, $throwable->getMessage()), previous: $throwable);
    }

    public static function forSymlinkedTargetDirectory(string $targetDirectory): self
    {
        return new self(\sprintf('Refusing to initialize a composer project in "%s": the target or its manifest path is a symlink.', $targetDirectory));
    }
}
