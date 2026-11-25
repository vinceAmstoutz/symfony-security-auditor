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
 * The pinned `composer.phar` the standalone binary installs provider bridges
 * with. Refuses a copy whose SHA-256 is not the pinned one.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ComposerPhar
{
    public const string VERSION = '2.8.12';

    public const string SHA256 = 'f446ea719708bb85fcbf4ef18def5d0515f1f9b4d703f6d820c9c1656e10a2f2';

    private const int CHECKSUM_PREFIX_LENGTH = 12;

    private const int STAGING_SUFFIX_BYTES = 8;

    public function __construct(
        private string $bundledPhar,
        private string $sha256 = self::SHA256,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public static function bundledPath(): string
    {
        return \sprintf('%s/resources/composer.phar', \dirname(__DIR__, 4));
    }

    public function isBundled(): bool
    {
        return is_file($this->bundledPhar);
    }

    /**
     * @return string Composer's entry script, unpacked from the PHAR, which Composer refuses to run from on phpmicro
     *
     * @throws BridgeInstallationFailedException
     */
    public function in(string $directory): string
    {
        $unpacked = \sprintf('%s/composer-%s-%s', $directory, self::VERSION, substr($this->sha256, 0, self::CHECKSUM_PREFIX_LENGTH));
        $entryScript = \sprintf('%s/bin/composer', $unpacked);

        if (!$this->isBundled()) {
            throw BridgeInstallationFailedException::forUnbundledComposerPhar(self::VERSION, $this->bundledPhar);
        }

        if (is_file($entryScript)) {
            return $entryScript;
        }

        $staging = \sprintf('%s.%s', $unpacked, bin2hex(random_bytes(self::STAGING_SUFFIX_BYTES)));
        $path = \sprintf('%s.phar', $staging);

        try {
            $this->unpack($path, $staging);
            $this->moveInPlace($staging, $unpacked, $entryScript);
        } catch (IOException $ioException) {
            throw BridgeInstallationFailedException::forUncopyableComposerPhar(self::VERSION, $directory, $ioException);
        }

        return $entryScript;
    }

    /**
     * Deletes the staged copy of the phar, which PHP closes once its last stream is.
     *
     * @throws BridgeInstallationFailedException
     * @throws IOException
     */
    private function unpack(string $path, string $staging): void
    {
        try {
            $this->filesystem->copy($this->bundledPhar, $path);
            $this->assertPinnedRelease($path);
            $this->filesystem->mirror(\sprintf('phar://%s', $path), $staging);
        } finally {
            $this->filesystem->remove($path);
        }
    }

    /**
     * Keeps the copy another run moved in place first.
     *
     * @throws IOException
     */
    private function moveInPlace(string $staging, string $unpacked, string $entryScript): void
    {
        try {
            $this->filesystem->rename($staging, $unpacked);
        } catch (IOException $ioException) {
            if (!is_file($entryScript)) {
                throw $ioException;
            }

            $this->filesystem->remove($staging);
        }
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    private function assertPinnedRelease(string $path): void
    {
        if (!hash_equals($this->sha256, (string) hash_file('sha256', $path))) {
            $this->filesystem->remove($path);

            throw BridgeInstallationFailedException::forTamperedComposerPhar(self::VERSION);
        }
    }
}
