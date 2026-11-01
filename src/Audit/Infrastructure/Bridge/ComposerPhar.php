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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge;

use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;

/**
 * The pinned `composer.phar` the standalone binary bundles and installs
 * provider bridges with, run on the binary's own PHP so `init` needs no PHP
 * or Composer on the host. PHP cannot run a PHAR held inside another, so it
 * is copied out to the bridge tree and checked against its SHA-256 there.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerPhar
{
    public const string VERSION = '2.8.12';

    public const string SHA256 = 'f446ea719708bb85fcbf4ef18def5d0515f1f9b4d703f6d820c9c1656e10a2f2';

    public function __construct(
        private string $bundledPhar,
        private string $sha256 = self::SHA256,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public static function bundledPath(): string
    {
        return \sprintf('%s/resources/composer.phar', \dirname(__DIR__, 4));
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function in(string $directory): string
    {
        $path = \sprintf('%s/composer.phar', $directory);
        $copy = \sprintf('%s.copy', $path);

        if (!is_file($this->bundledPhar)) {
            throw BridgeInstallationFailedException::forUnbundledComposerPhar(self::VERSION, $this->bundledPhar);
        }

        try {
            $this->filesystem->copy($this->bundledPhar, $copy);
        } catch (IOException $ioException) {
            throw BridgeInstallationFailedException::forUncopyableComposerPhar(self::VERSION, $directory, $ioException);
        }

        if (!$this->isPinnedRelease($copy)) {
            $this->filesystem->remove($copy);

            throw BridgeInstallationFailedException::forTamperedComposerPhar(self::VERSION);
        }

        $this->filesystem->rename($copy, $path, true);

        return $path;
    }

    private function isPinnedRelease(string $path): bool
    {
        return hash_equals($this->sha256, (string) hash_file('sha256', $path));
    }
}
