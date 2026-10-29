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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ReleaseClientInterface;

/**
 * The pinned `composer.phar` the standalone binary installs provider bridges
 * with, run on the binary's own PHP so `init` needs no PHP or Composer on the
 * host. Downloaded on first use and checked against its SHA-256.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerPhar
{
    public const string VERSION = '2.8.12';

    private const string SHA256 = 'f446ea719708bb85fcbf4ef18def5d0515f1f9b4d703f6d820c9c1656e10a2f2';

    private const string DOWNLOAD_URL = 'https://getcomposer.org/download/%s/composer.phar';

    public function __construct(
        private ReleaseClientInterface $releaseClient,
        private string $sha256 = self::SHA256,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @throws BridgeInstallationFailedException
     */
    public function in(string $directory): string
    {
        $path = \sprintf('%s/composer.phar', $directory);
        if ($this->isPinnedRelease($path)) {
            return $path;
        }

        $download = \sprintf('%s.download', $path);

        try {
            $this->filesystem->mkdir($directory);
            $this->releaseClient->download(\sprintf(self::DOWNLOAD_URL, self::VERSION), $download);
        } catch (IOException|SelfUpdateFailedException $failure) {
            throw BridgeInstallationFailedException::forUndownloadableComposerPhar(self::VERSION, $failure);
        }

        if (!$this->isPinnedRelease($download)) {
            $this->filesystem->remove($download);

            throw BridgeInstallationFailedException::forTamperedComposerPhar(self::VERSION);
        }

        $this->filesystem->rename($download, $path, true);

        return $path;
    }

    private function isPinnedRelease(string $path): bool
    {
        return is_file($path) && hash_equals($this->sha256, (string) hash_file('sha256', $path));
    }
}
